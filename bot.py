#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IMS SMS Forwarder (fixed)
- Logs into https://imssms.org/login (handles CSRF token & simple math captcha if present)
- Loads dashboard to obtain session cookies
- Requests /client/res/data_smscdr.php with proper headers (Referer, X-Requested-With)
- Safe JSON parsing (won't crash on HTML)
- Dedup via MongoDB (optional) or local JSON file
- Robust loop + detailed logs for debugging
"""

import os
import time
import json
import tempfile
import logging
import re
from hashlib import sha1
from datetime import datetime, timezone
import requests
from bs4 import BeautifulSoup

# Optional Mongo (import lazily)
try:
    from pymongo import MongoClient
except Exception:
    MongoClient = None

# --- Config (env vars with sensible fallbacks) ---
BOT_TOKEN = os.getenv("IMSSMS_BOT_TOKEN") or os.getenv("BOT_TOKEN")
# supports either single CHAT_ID or comma-separated IMSSMS_CHAT_IDS
CHAT_IDS_RAW = os.getenv("IMSSMS_CHAT_IDS") or os.getenv("CHAT_ID") or os.getenv("CHAT_IDS", "")
CHAT_IDS = [c.strip() for c in CHAT_IDS_RAW.split(",") if c.strip()]

IMS_USERNAME = os.getenv("IMS_USERNAME") or os.getenv("IMS_USER") or os.getenv("IMS_LOGIN")
IMS_PASSWORD = os.getenv("IMS_PASSWORD") or os.getenv("IMS_PASS")

BASE_URL = os.getenv("BASE_URL", "https://imssms.org").rstrip("/")
LOGIN_PATH = os.getenv("LOGIN_PATH", "/login")
LOGIN_URL = f"{BASE_URL}{LOGIN_PATH}"

DATA_API_PATH = os.getenv("IMSSMS_DATA_API_PATH", "/client/res/data_smscdr.php")
DATA_URL = f"{BASE_URL}{DATA_API_PATH}"

MONGO_URI = os.getenv("MONGO_URI") or os.getenv("IMSSMS_MONGO_URI") or ""
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", os.getenv("IMSSMS_POLL_INTERVAL", "15")))
STATE_FILE = os.getenv("STATE_FILE", "seen_imssms.json")

# --- Logging ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger("imssms-bot")

# --- Session + headers ---
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (IMS-Bot/1.0)",
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "X-Requested-With": "XMLHttpRequest",
})

# --- OTP regex & math captcha regex ---
OTP_RE = re.compile(r"\b\d{3,8}\b")
MATH_Q_RE = re.compile(r'What is\s*([0-9]+)\s*([+\-xX*\/])\s*([0-9]+)', re.I)

# --- Mongo (optional) ---
use_mongo = False
mongo_col = None
if MONGO_URI and MongoClient:
    try:
        # Try connecting; if SRV DNS fails this will raise
        client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        client.server_info()
        db = client.get_database("imssms_bot")
        mongo_col = db.get_collection("messages")
        mongo_col.create_index("msg_id", unique=True)
        use_mongo = True
        log.info("✅ MongoDB connected")
    except Exception as e:
        log.warning("MongoDB connect fail: %s", e)
        use_mongo = False
else:
    if MONGO_URI and not MongoClient:
        log.warning("pymongo not installed; Mongo disabled. Install pymongo if you want Mongo dedupe.")

# --- local seen storage ---
def load_seen():
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r") as f:
                data = json.load(f)
                return set(data)
    except Exception:
        log.exception("Failed to load seen state file")
    return set()

def save_seen(seen_set):
    try:
        fd, tmp = tempfile.mkstemp()
        with os.fdopen(fd, "w") as f:
            json.dump(list(seen_set), f)
        os.replace(tmp, STATE_FILE)
    except Exception:
        log.exception("Failed to save seen state")

seen = load_seen()

# --- helper: solve simple math captcha if present ---
def solve_math_from_text(text):
    m = MATH_Q_RE.search(text or "")
    if not m:
        return None
    a = int(m.group(1)); op = m.group(2); b = int(m.group(3))
    if op in ("+",):
        return str(a + b)
    if op in ("-",):
        return str(a - b)
    if op in ("x", "X", "*"):
        return str(a * b)
    if op == "/":
        return str(a // b if b != 0 else 0)
    return None

# --- telegram send (supports multiple chat ids) ---
def send_telegram(text):
    if not BOT_TOKEN or not CHAT_IDS:
        log.warning("BOT_TOKEN or CHAT_IDS not configured; skipping Telegram send")
        return
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    for cid in CHAT_IDS:
        try:
            resp = requests.post(url, data={"chat_id": cid, "text": text, "parse_mode": "Markdown"}, timeout=10)
            if resp.status_code != 200:
                log.warning("Telegram send returned %s: %s", resp.status_code, resp.text[:200])
        except Exception as e:
            log.warning("Failed to send Telegram message: %s", e)

# --- login flow: GET login page, detect token/captcha, POST to form action (or LOGIN_URL) ---
def ims_login():
    if not IMS_USERNAME or not IMS_PASSWORD:
        log.error("IMS_USERNAME/IMS_PASSWORD not set in env")
        return False
    try:
        r = session.get(LOGIN_URL, timeout=15)
        r.raise_for_status()
        soup = BeautifulSoup(r.text or "", "html.parser")
        form = soup.find("form")
        action = form.get("action") if form and form.get("action") else LOGIN_URL
        if action.startswith("/"):
            action = BASE_URL + action
        # find token inputs if present
        payload = {}
        # common field names
        payload_field_user = None
        payload_field_pass = None
        for inp in (form.find_all("input") if form else []):
            name = inp.get("name") or ""
            itype = inp.get("type") or "text"
            # choose username field
            if not payload_field_user and ("user" in name.lower() or "email" in name.lower() or "login" in name.lower()):
                payload_field_user = name
            if not payload_field_pass and ("pass" in name.lower() or "pwd" in name.lower()):
                payload_field_pass = name
            # copy hidden tokens
            if itype == "hidden" and name:
                payload[name] = inp.get("value", "")
        # fallback names
        if not payload_field_user:
            payload_field_user = "username"
        if not payload_field_pass:
            payload_field_pass = "password"
        payload[payload_field_user] = IMS_USERNAME
        payload[payload_field_pass] = IMS_PASSWORD
        # detect simple math captcha on page and add common field names
        math_answer = solve_math_from_text(soup.get_text(" ", strip=True))
        if math_answer is not None:
            # add typical captcha field names (try a few)
            for field in ("captcha", "answer", "math", "verification"):
                payload.setdefault(field, math_answer)
        # POST to login action
        post = session.post(action, data=payload, allow_redirects=True, timeout=15)
        log.info("✅ Login attempted (status %s)", post.status_code)
        log.info("Cookies after login: %s", session.cookies.get_dict())
        # attempt to load dashboard to ensure we have session context
        dash = session.get(f"{BASE_URL}/client/SMSDashboard", timeout=15)
        log.info("Dashboard load status: %s", dash.status_code)
        return post.status_code in (200, 302)
    except Exception as e:
        log.exception("Login error")
        return False

# --- fetch API with correct headers & referer; safe JSON parsing ---
def fetch_sms_window(minutes_back=10):
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
            "_": str(int(time.time() * 1000))
        }
        headers = {
            "Referer": f"{BASE_URL}/client/SMSDashboard",
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Cache-Control": "no-store, no-cache, must-revalidate",
        }
        resp = session.get(DATA_URL, params=params, headers=headers, timeout=15)
        log.info("Fetch status: %s", resp.status_code)
        ct = resp.headers.get("Content-Type", "")
        text_snip = (resp.text or "")[:400].replace("\n", " ")
        log.debug("Fetch content snippet: %s", text_snip)
        # Only try json if looks like JSON (fast check)
        if resp.status_code == 200 and (ct.startswith("application/json") or resp.text.strip().startswith("{")):
            try:
                j = resp.json()
                return j.get("aaData", []) if isinstance(j, dict) else []
            except Exception:
                log.exception("JSON parse failed; raw begins: %s", (resp.text or "")[:200])
                return []
        else:
            log.warning("Not JSON response (Content-Type=%s). Response starts with: %s", ct, (resp.text or "")[:200])
            # If server returned HTML redirect or login page, likely session expired
            if "<form" in (resp.text or "") or "login" in (resp.url or ""):
                log.info("Session likely expired or server redirected. Re-login needed.")
            return []
    except Exception:
        log.exception("Fetch error")
        return []

# --- dedupe helpers ---
def already_seen_id(mid):
    if use_mongo and mongo_col:
        try:
            return mongo_col.find_one({"msg_id": mid}) is not None
        except Exception:
            log.exception("Mongo read fail")
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
            log.exception("Mongo insert fail")
    seen.add(mid)

# --- format & forward ---
def format_and_forward(row):
    # expected aaData row: [timestamp, operator, number, service, message, client, ...]
    try:
        ts = row[0] if len(row) > 0 else ""
        operator = row[1] if len(row) > 1 else ""
        number = row[2] if len(row) > 2 else ""
        service = row[3] if len(row) > 3 else ""
        message = row[4] if len(row) > 4 else ""
    except Exception:
        log.warning("Unexpected row shape: %s", row)
        return
    mid = sha1(f"{ts}|{number}|{message}".encode()).hexdigest()
    if already_seen_id(mid):
        return
    # extract OTP
    otps = OTP_RE.findall(message or "")
    otp = otps[-1] if otps else "N/A"
    text = (
        f"✅ *New OTP*\n"
        f"🌐 Site: {BASE_URL}\n"
        f"🕰 {ts}\n"
        f"📞 {number}\n"
        f"🔢 OTP: `{otp}`\n"
        f"📡 Operator: {operator}\n"
        f"💬 {message}"
    )
    send_telegram(text)
    mark_seen_id(mid, {"ts": ts, "num": number, "otp": otp})
    log.info("Forwarded %s (%s)", number, otp)

# --- main loop ---
def main():
    # quick env check
    if not BOT_TOKEN or not CHAT_IDS:
        log.error("Missing BOT_TOKEN or CHAT_IDS. Set IMSSMS_BOT_TOKEN and IMSSMS_CHAT_IDS (comma separated)")
        return
    if not IMS_USERNAME or not IMS_PASSWORD:
        log.error("Missing IMS_USERNAME/IMS_PASSWORD - cannot login")
        return

    # login + warm dashboard to pick up cookies and session
    success = ims_login()
    if not success:
        log.error("Login failed. Exiting (will be retried by outer loop).")
        return

    log.info("🚀 Bot started polling %s (api=%s)", BASE_URL, DATA_API_PATH)
    while True:
        try:
            rows = fetch_sms_window(minutes_back=15)
            if rows:
                # aaData often contains trailing garbage row like ["0,0,0,7",0,0,...] ignore non-list rows
                for r in rows:
                    if isinstance(r, list):
                        format_and_forward(r)
            time.sleep(POLL_INTERVAL)
        except KeyboardInterrupt:
            log.info("Interrupted by user")
            break
        except Exception:
            log.exception("Main loop error - will continue after short sleep")
            time.sleep(10)

# outer retry loop so Heroku doesn't exit if login fails temporarily
if __name__ == "__main__":
    while True:
        try:
            main()
        except Exception:
            log.exception("Fatal error in main - retrying in 30s")
            time.sleep(30)
