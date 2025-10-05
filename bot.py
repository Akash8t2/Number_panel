#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IMS SMS Forwarder - robust login + cookie/CSRF handling
Fixes:
 - correctly resolves relative form actions (urljoin)
 - posts login with Referer/Origin/X-Requested-With headers
 - collects hidden inputs / CSRF / math captcha answers automatically
 - logs helpful snippets on 403 so you can see Cloudflare/HTML challenge
 - non-fatal Mongo handling
 - safe JSON fetch for data_smscdr.php
"""

import os
import time
import json
import tempfile
import logging
import re
from hashlib import sha1
from datetime import datetime, timezone, timedelta
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

# optional pymongo import
try:
    from pymongo import MongoClient
except Exception:
    MongoClient = None

# --- config via env ---
BASE_URL = os.getenv("BASE_URL", "https://imssms.org").rstrip("/")
LOGIN_PATH = os.getenv("LOGIN_PATH", "/login")            # usually "/login"
DATA_API_PATH = os.getenv("IMSSMS_DATA_API_PATH", "/client/res/data_smscdr.php")
LOGIN_URL = urljoin(BASE_URL, LOGIN_PATH)
DATA_URL = urljoin(BASE_URL, DATA_API_PATH)

BOT_TOKEN = os.getenv("IMSSMS_BOT_TOKEN") or os.getenv("BOT_TOKEN")
CHAT_IDS_RAW = os.getenv("IMSSMS_CHAT_IDS") or os.getenv("CHAT_ID") or os.getenv("CHAT_IDS", "")
CHAT_IDS = [c.strip() for c in CHAT_IDS_RAW.split(",") if c.strip()]

IMS_USERNAME = os.getenv("IMS_USERNAME") or os.getenv("IMS_USER") or os.getenv("IMS_LOGIN")
IMS_PASSWORD = os.getenv("IMS_PASSWORD") or os.getenv("IMS_PASS")

MONGO_URI = os.getenv("MONGO_URI") or os.getenv("IMSSMS_MONGO_URI") or ""
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "15"))
STATE_FILE = os.getenv("STATE_FILE", "seen_imssms.json")

# --- logging ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger("imssms-fixed")

# --- session default headers ---
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
})

# regex
OTP_RE = re.compile(r"\b\d{3,8}\b")
MATH_Q_RE = re.compile(r'What is\s*([0-9]+)\s*([+\-xX*\/])\s*([0-9]+)', re.I)

# Mongo setup (non-fatal)
use_mongo = False
mongo_col = None
if MONGO_URI and MongoClient:
    try:
        mc = MongoClient(MONGO_URI, serverSelectionTimeoutMS=4000)
        mc.server_info()
        db = mc.get_database("imssms_bot")
        mongo_col = db.get_collection("messages")
        mongo_col.create_index("msg_id", unique=True)
        use_mongo = True
        log.info("✅ MongoDB connected")
    except Exception as e:
        log.warning("MongoDB connection failed (continuing without it): %s", e)
else:
    if MONGO_URI:
        log.warning("MONGO_URI provided but pymongo not installed - ignoring Mongo")

# --- seen local store ---
def load_seen():
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r") as f:
                return set(json.load(f))
    except Exception:
        log.exception("Failed to load seen file")
    return set()

def save_seen(seen_set):
    try:
        fd, tmp = tempfile.mkstemp()
        with os.fdopen(fd, "w") as f:
            json.dump(list(seen_set), f)
        os.replace(tmp, STATE_FILE)
    except Exception:
        log.exception("Failed to save seen file")

seen = load_seen()

# --- helper to solve math captcha ---
def solve_math(text):
    m = MATH_Q_RE.search(text or "")
    if not m:
        return None
    a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
    if op == "+":
        return str(a + b)
    if op == "-":
        return str(a - b)
    if op in ("x", "X", "*"):
        return str(a * b)
    if op == "/":
        return str(a // b if b != 0 else 0)
    return None

# --- Telegram send ---
def send_telegram(msg: str):
    if not BOT_TOKEN or not CHAT_IDS:
        log.warning("Telegram token or chat ids missing; skipping send")
        return
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    for cid in CHAT_IDS:
        try:
            resp = requests.post(url, data={"chat_id": cid, "text": msg, "parse_mode": "Markdown"}, timeout=10)
            if resp.status_code != 200:
                log.warning("Telegram send failure %s: %s", resp.status_code, resp.text[:200])
        except Exception as e:
            log.warning("Telegram send exception: %s", e)

# --- robust login that resolves relative actions and posts hidden inputs ---
def ims_login(max_attempts=3):
    if not IMS_USERNAME or not IMS_PASSWORD:
        log.error("IMS_USERNAME / IMS_PASSWORD not set")
        return False

    attempt = 0
    backoff = 5
    while attempt < max_attempts:
        attempt += 1
        try:
            log.info("GET login page: %s", LOGIN_URL)
            r = session.get(LOGIN_URL, timeout=15)
            # If returned 403, likely server block or Cloudflare
            if r.status_code == 403:
                log.error("Login GET returned 403 Forbidden. Response snippet:\n%s", (r.text or "")[:800])
                return False
            r.raise_for_status()
            soup = BeautifulSoup(r.text or "", "html.parser")

            # find <form> (prefer form with input names)
            form = soup.find("form")
            action = form.get("action") if form and form.get("action") else LOGIN_URL
            action_url = urljoin(LOGIN_URL, action)

            # gather form fields (including hidden tokens)
            payload = {}
            username_field = None
            password_field = None
            if form:
                for inp in form.find_all("input"):
                    name = inp.get("name")
                    typ = (inp.get("type") or "text").lower()
                    if not name:
                        continue
                    # detect username/password field heuristically
                    lname = name.lower()
                    if typ in ("text",) and (("user" in lname) or ("email" in lname) or ("login" in lname)) and not username_field:
                        username_field = name
                    if typ in ("password",) and not password_field:
                        password_field = name
                    # include existing value for hidden fields
                    if typ in ("hidden",):
                        payload[name] = inp.get("value", "")

            # fallback common names
            if not username_field:
                username_field = "username"
            if not password_field:
                password_field = "password"
            payload[username_field] = IMS_USERNAME
            payload[password_field] = IMS_PASSWORD

            # try math captcha if present on page text
            math_answer = solve_math(soup.get_text(" ", strip=True))
            if math_answer is not None:
                # common field names for captcha/answer
                for field in ("captcha", "answer", "math", "verification"):
                    if field not in payload:
                        payload.setdefault(field, math_answer)

            # set headers for POST: include Origin & Referer & X-Requested-With
            headers = {
                "Referer": LOGIN_URL,
                "Origin": BASE_URL,
                "X-Requested-With": "XMLHttpRequest",
                "User-Agent": session.headers.get("User-Agent"),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
            }

            log.info("POST login to: %s (attempt %d)", action_url, attempt)
            post = session.post(action_url, data=payload, headers=headers, allow_redirects=True, timeout=20)

            # if 403 on POST, log and stop attempts (likely anti-bot)
            if post.status_code == 403:
                log.error("Login POST returned 403 Forbidden. Response snippet:\n%s", (post.text or "")[:1000])
                # if it's Cloudflare or JS challenge, no simple script will pass it; need headless browser or manual cookie
                return False

            # check if we got a session cookie or dashboard success
            log.info("Login POST status: %s", post.status_code)
            log.info("Cookies after login: %s", session.cookies.get_dict())

            # try to load dashboard to ensure we have a valid session
            dash = session.get(urljoin(BASE_URL, "/client/SMSDashboard"), timeout=15)
            log.info("Dashboard GET status: %s", dash.status_code)
            if dash.status_code == 200 and "SMSDashboard" in (dash.text or ""):
                log.info("Login appears successful (dashboard reachable)")
                return True

            # some sites redirect to a different path after login; treat 200/302 as potential success
            if post.status_code in (200, 302):
                # small heuristic: if session cookie present and dashboard redirects
                if session.cookies.get_dict():
                    log.info("Login likely OK (cookies present).")
                    return True

            # otherwise retry after backoff
            log.warning("Login attempt didn't confirm dashboard; retrying after %ds", backoff)
            time.sleep(backoff)
            backoff *= 2
        except requests.exceptions.RequestException as e:
            log.exception("Network/login request failed (attempt %d): %s", attempt, e)
            time.sleep(backoff)
            backoff *= 2
        except Exception:
            log.exception("Unexpected error during login")
            time.sleep(backoff)
            backoff *= 2
    log.error("Exceeded max login attempts")
    return False

# --- fetch function with proper Referer and JSON-safe handling ---
def fetch_sms(minutes_back=15):
    try:
        now = datetime.now(timezone.utc)
        f1 = (now - timedelta(minutes=minutes_back)).strftime("%Y-%m-%d %H:%M:%S")
        f2 = now.strftime("%Y-%m-%d %H:%M:%S")
        params = {
            "fdate1": f1,
            "fdate2": f2,
            "frange": "",
            "fnum": "",
            "fcli": "",
            "fgdate": "",
            "fgmonth": "",
            "fgrange": "",
            "fgnumber": "",
            "fgcli": "",
            "fg": "0",
            "sEcho": "1",
            "iColumns": "7",
            "sColumns": ",,,,,,",
            "iDisplayStart": "0",
            "iDisplayLength": "25",
            "iSortCol_0": "0",
            "sSortDir_0": "desc",
            "iSortingCols": "1",
            "_": str(int(time.time() * 1000)),
        }
        headers = {
            "Referer": urljoin(BASE_URL, "/client/SMSDashboard"),
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
        }
        r = session.get(DATA_URL, params=params, headers=headers, timeout=15)
        log.debug("Fetch status: %s; content-type: %s", r.status_code, r.headers.get("Content-Type"))
        snippet = (r.text or "")[:800].replace("\n", " ")
        log.debug("Fetch snippet: %s", snippet)
        if r.status_code != 200:
            log.warning("Fetch non-200: %s", r.status_code)
            # If 403/HTML, session probably expired -> force re-login upstream
            return []
        # only parse JSON if content-type indicates JSON or starts with {
        ct = r.headers.get("Content-Type", "")
        if ct.startswith("application/json") or (r.text and r.text.strip().startswith("{")):
            try:
                j = r.json()
                return j.get("aaData", []) if isinstance(j, dict) else []
            except Exception:
                log.exception("JSON parse failed; snippet: %s", snippet)
                return []
        else:
            log.warning("Fetch returned HTML (not JSON); snippet: %s", snippet)
            return []
    except Exception:
        log.exception("Fetch exception")
        return []

# --- dedupe helpers ---
def already_seen_id(mid):
    if use_mongo and mongo_col:
        try:
            return mongo_col.find_one({"msg_id": mid}) is not None
        except Exception:
            log.exception("Mongo read error")
            return False
    return mid in seen

def mark_seen_id(mid, payload=None):
    if use_mongo and mongo_col:
        try:
            doc = {"msg_id": mid}
            if payload:
                doc["payload"] = payload
            mongo_col.insert_one(doc)
            return
        except Exception:
            log.exception("Mongo insert error")
    seen.add(mid)

# --- format + forward ---
def format_and_forward(row):
    # aaData row expected: [timestamp, operator, number, service, message, client, ...]
    try:
        ts = row[0] if len(row) > 0 else ""
        operator = row[1] if len(row) > 1 else ""
        number = row[2] if len(row) > 2 else ""
        service = row[3] if len(row) > 3 else ""
        message = row[4] if len(row) > 4 else ""
    except Exception:
        log.warning("Malformed row: %s", row)
        return

    mid = sha1(f"{ts}|{number}|{message}".encode()).hexdigest()
    if already_seen_id(mid):
        return

    otps = OTP_RE.findall(message or "")
    otp = otps[-1] if otps else "N/A"
    text = (
        f"✅ *New OTP*\n"
        f"🌐 {BASE_URL}\n"
        f"🕰 {ts}\n"
        f"📞 {number}\n"
        f"🔢 OTP: `{otp}`\n"
        f"📡 {operator}\n"
        f"💬 {message}"
    )
    send_telegram(text)
    mark_seen_id(mid, {"ts": ts, "num": number, "otp": otp})
    log.info("Forwarded %s (%s)", number, otp)

# --- main loop (with login retry/backoff) ---
def main_loop():
    if not BOT_TOKEN or not CHAT_IDS:
        log.error("Missing BOT_TOKEN or CHAT_IDS (IMSSMS_BOT_TOKEN / IMSSMS_CHAT_IDS)")
        return
    if not IMS_USERNAME or not IMS_PASSWORD:
        log.error("Missing IMS_USERNAME / IMS_PASSWORD")
        return

    # outer retry to keep process alive
    while True:
        try:
            if not ims_login():
                log.error("Login failed - sleeping 60s before retry")
                time.sleep(60)
                continue

            log.info("🚀 Polling started (api=%s)", DATA_URL)
            while True:
                rows = fetch_sms(minutes_back=15)
                if rows:
                    for r in rows:
                        if isinstance(r, list):
                            format_and_forward(r)
                time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            log.info("Interrupted by user")
            break
        except Exception:
            log.exception("Main loop error - will retry login after short sleep")
            time.sleep(30)

if __name__ == "__main__":
    main_loop()
