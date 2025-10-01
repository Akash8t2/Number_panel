#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Final OTP forwarder (Heroku-ready)
Features:
 - auto CSRF login (username/password)
 - optional cookie injection via COOKIES env var ("k=v; k2=v2")
 - MongoDB storage (unique id index)
 - skip old OTPs on startup (only forward new arrivals)
 - robust dedupe (Mongo + local seen set)
 - Telegram rate-limit handling (retry_after)
 - session reuse and exponential backoff on login/fetch failures
"""

from __future__ import annotations
import os
import time
import json
import logging
import re
import random
import string
from hashlib import sha1
from datetime import datetime, timedelta, timezone
from typing import Optional, Dict, Set
from urllib.parse import urljoin
import tempfile

import requests
from bs4 import BeautifulSoup
from pymongo import MongoClient, errors

# ---------------- CONFIG ----------------
BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_IDS = os.getenv("CHAT_IDS", "")  # comma-separated
USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")
COOKIES_RAW = os.getenv("COOKIES", "")  # optional cookie string "k=v; k2=v2"
SITE_BASE = os.getenv("SITE_BASE", "http://45.82.67.20").rstrip("/")
LOGIN_PATH = os.getenv("LOGIN_PATH", "/ints/login")
SIGNIN_PATH = os.getenv("SIGNIN_PATH", "/ints/signin")
DASH_PATH = os.getenv("DASH_PATH", "/ints/agent/SMSCDRStats")
DATA_API_PATH = os.getenv("DATA_API_PATH", "/ints/agent/res/data_smscdr.php")

POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "1.5"))
STATE_FILE = os.getenv("STATE_FILE", "processed_sms_ids.json")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "15"))
USER_AGENT = os.getenv("USER_AGENT", "Mozilla/5.0 (X11; Linux x86_64)")
MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://BrandedSupportGroup:BRANDED_WORLD@cluster0.v4odcq9.mongodb.net/?retryWrites=true&w=majority")
MONGO_DB = os.getenv("MONGO_DB", "otp_forwarder")
MONGO_COLL = os.getenv("MONGO_COLL", "otps")

FORWARD_IF_NO_CODE = os.getenv("FORWARD_IF_NO_CODE", "false").lower() in ("1", "true", "yes")
MAX_RELOGIN_RETRIES = int(os.getenv("MAX_RELOGIN_RETRIES", "6"))

# Derived
LOGIN_URL = urljoin(SITE_BASE + "/", LOGIN_PATH.lstrip("/"))
SIGNIN_URL = urljoin(SITE_BASE + "/", SIGNIN_PATH.lstrip("/"))
DASH_URL = urljoin(SITE_BASE + "/", DASH_PATH.lstrip("/"))
DATA_API_URL = urljoin(SITE_BASE + "/", DATA_API_PATH.lstrip("/"))
CHAT_IDS_LIST = [c.strip() for c in (CHAT_IDS or "").split(",") if c.strip()]
TELEGRAM_SEND_URL = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

# Logging
logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s", level=logging.INFO)
logger = logging.getLogger("otp_forwarder_final")

# Regex
OTP_HYPH = re.compile(r'(\d{3}-\d{3})')
OTP_PLAIN = re.compile(r'\b(\d{3,8})\b')

# ---------------- small helpers ----------------
def random_tail(n=8):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def parse_cookies(cookie_str: str) -> Dict[str, str]:
    cookies = {}
    if not cookie_str:
        return cookies
    for part in cookie_str.split(";"):
        if "=" in part:
            k, v = part.split("=", 1)
            cookies[k.strip()] = v.strip()
    return cookies

INJECTED_COOKIES = parse_cookies(COOKIES_RAW)

# ---------------- seen state (local + file) ----------------
def load_seen() -> Set[str]:
    if not os.path.exists(STATE_FILE):
        return set()
    try:
        with open(STATE_FILE, "r") as f:
            data = json.load(f)
            return set(data) if isinstance(data, list) else set()
    except Exception:
        return set()

def save_seen_atomic(seen_set: Set[str]):
    try:
        dirpath = os.path.dirname(os.path.abspath(STATE_FILE)) or "."
        fd, tmp = tempfile.mkstemp(dir=dirpath)
        with os.fdopen(fd, "w") as f:
            json.dump(list(seen_set), f)
        os.replace(tmp, STATE_FILE)
    except Exception as e:
        logger.debug("Could not save state file: %s", e)

seen: Set[str] = load_seen()

# ---------------- mongo ----------------
mongo_coll = None
try:
    client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    client.admin.command("ping")
    db = client[MONGO_DB]
    mongo_coll = db[MONGO_COLL]
    # ensure unique index on id
    mongo_coll.create_index("id", unique=True)
    logger.info("MongoDB: connected and index ensured")
except Exception as e:
    logger.error("MongoDB connection failed: %s", e)
    mongo_coll = None

# ---------------- session/login ----------------
session: Optional[requests.Session] = None
_last_login_time = 0
_login_fail_count = 0
_backoff_base = 2.0
_last_successful_check = 0

def create_session_and_login(force: bool = False) -> Optional[requests.Session]:
    """
    Create or reuse session. If cookie injection provided, try that first.
    Uses CSRF token auto-detection when logging in via username/password.
    Applies exponential backoff on repeated failures.
    """
    global session, _last_login_time, _login_fail_count, _backoff_base, _last_successful_check

    now = time.time()
    # reuse if recent and exists
    if session and not force and (now - _last_login_time) < 60:
        return session

    # backoff if repeated failures
    if _login_fail_count >= MAX_RELOGIN_RETRIES:
        wait = min(_backoff_base ** _login_fail_count, 300)
        logger.warning("Login failing repeatedly; sleeping backoff %s sec", int(wait))
        time.sleep(wait)

    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Referer": SITE_BASE})

    # try cookie injection first (if provided)
    if INJECTED_COOKIES:
        try:
            s.cookies.update(INJECTED_COOKIES)
            chk = s.get(DASH_URL, timeout=REQUEST_TIMEOUT)
            if chk.status_code < 400 and "sms" in (chk.text or "").lower():
                session = s
                _last_login_time = time.time()
                _login_fail_count = 0
                logger.info("Session initialized from provided cookies.")
                return session
            else:
                logger.info("Injected cookies did not authenticate; falling back to login.")
        except Exception as e:
            logger.warning("Injected-cookies dashboard check failed: %s", e)

    # require username/password to login
    if not USERNAME or not PASSWORD:
        logger.error("USERNAME/PASSWORD not set and cookies not sufficient.")
        return None

    try:
        r = s.get(LOGIN_URL, timeout=REQUEST_TIMEOUT)
        page = r.text or ""
        soup = BeautifulSoup(page, "html.parser")
        token_input = soup.find("input", {"name": "_token"}) or soup.find("input", {"name": "csrf_token"}) or soup.find("input", {"name": "csrf"})
        payload = {"username": USERNAME, "password": PASSWORD}
        if token_input and token_input.get("name") and token_input.get("value"):
            payload[token_input.get("name")] = token_input.get("value")
        headers = {"User-Agent": USER_AGENT, "Referer": LOGIN_URL, "Origin": SITE_BASE}
        post = s.post(SIGNIN_URL, data=payload, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        # try dashboard to confirm
        chk = s.get(DASH_URL, timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT, "Referer": LOGIN_URL})
        if chk.status_code < 400 and ("sms" in (chk.text or "").lower() or "dashboard" in (chk.text or "").lower()):
            session = s
            _last_login_time = time.time()
            _login_fail_count = 0
            _last_successful_check = time.time()
            logger.info("Login successful and dashboard reachable.")
            return session
        else:
            _login_fail_count += 1
            logger.warning("Login POST completed but dashboard not reachable (status %s).", chk.status_code)
            return None
    except Exception as e:
        _login_fail_count += 1
        logger.warning("Login attempt failed: %s", e)
        return None

# ---------------- fetch data rows ----------------
def fetch_data_rows() -> Optional[list]:
    """
    Returns aaData list or None on error/need to retry.
    Uses a small window (last 2 minutes by default) to capture live messages.
    """
    global session
    if session is None:
        session = create_session_and_login(force=True)
        if session is None:
            return None

    now = datetime.now(tz=timezone.utc)
    fdate2 = now.strftime("%Y-%m-%d %H:%M:%S")
    # we only look back a couple minutes to avoid sending old messages
    lookback_minutes = 2
    fdate1 = (now - timedelta(minutes=lookback_minutes)).strftime("%Y-%m-%d %H:%M:%S")

    params = {
        "fdate1": fdate1,
        "fdate2": fdate2,
        "frange": "",
        "fclient": "",
        "fnum": "",
        "fcli": "",
        "fgdate": "",
        "fgmonth": "",
        "fgrange": "",
        "fgclient": "",
        "fgnumber": "",
        "fgcli": "",
        "fg": "0",
        "sEcho": "1",
        "iColumns": "9",
        "iDisplayStart": "0",
        "iDisplayLength": "50",
        "_": str(int(time.time() * 1000))
    }

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": DASH_URL
    }

    try:
        r = session.get(DATA_API_URL, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        body = r.text or ""
        # if HTML returned -> session probably expired
        if body.strip().lower().startswith("<") and "login" in body.lower():
            logger.warning("Data API returned HTML (login page). Marking session invalid.")
            session = None
            return None
        data = r.json()
        aa = data.get("aaData", [])
        return aa
    except ValueError:
        logger.warning("Data API returned non-JSON content.")
        return None
    except Exception as e:
        logger.warning("Fetch failed: %s", e)
        session = None
        return None

# ---------------- parse / format ----------------
def parse_row_to_entry(row) -> Optional[dict]:
    try:
        ts = row[0] if len(row) > 0 else ""
        operator = row[1] if len(row) > 1 else ""
        number_raw = row[2] if len(row) > 2 else ""
        service_field = row[3] if len(row) > 3 else ""
        client = row[4] if len(row) > 4 else ""
        message_raw = row[5] if len(row) > 5 else ""
    except Exception:
        return None

    number = str(number_raw) if number_raw is not None else ""
    message = str(message_raw) if message_raw is not None else ""
    number = number.strip()

    m = OTP_HYPH.search(message)
    if m:
        code = m.group(1)
        code_plain = code.replace("-", "")
    else:
        m2 = OTP_PLAIN.search(message)
        code = m2.group(1) if m2 else "N/A"
        code_plain = code

    uid = sha1(f"{number}|{message}|{ts}".encode("utf-8")).hexdigest()
    service_guess = str(service_field).strip() if service_field and str(service_field).strip() not in ("", "0", "-") else detect_service(message)

    entry = {
        "id": uid,
        "time": ts,
        "operator": str(operator),
        "number": number,
        "service": service_guess,
        "client": str(client),
        "message": message,
        "code": code,
        "code_plain": code_plain,
        "fetched_at": datetime.utcnow()
    }
    return entry

def detect_service(text: str) -> str:
    if not text:
        return "Unknown"
    t = text.lower()
    if "whatsapp" in t: return "WhatsApp"
    if "telegram" in t: return "Telegram"
    if "gmail" in t or "google" in t: return "Gmail"
    if "facebook" in t: return "Facebook"
    return "Unknown"

def format_message(entry: dict) -> str:
    number = str(entry.get("number", "N/A"))
    code = str(entry.get("code", "N/A"))
    service = str(entry.get("service", "Unknown"))
    country = str(entry.get("operator", "Unknown"))
    ts = str(entry.get("time", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")))
    msg = str(entry.get("message", ""))
    tail = random_tail(6)

    login_link = ""
    if ("telegram" in service.lower() or "telegram" in msg.lower()) and entry.get("code_plain") not in (None, "N/A"):
        login_link = f"\nYou can also tap: https://t.me/login/{entry.get('code_plain')}\n"

    text = (
        "🔔 Live OTP received\n\n"
        f"📞 Number: {number}\n"
        f"🔑 Code: {code}\n"
        f"🏆 Service: {service}\n"
        f"🌎 Country: {country}\n"
        f"⏳ Time: {ts}\n\n"
        f"💬 Message:\n{msg}\n{login_link}{tail}"
    )
    return text

# ---------------- Telegram send (rate-limit aware) ----------------
def safe_send_telegram_once(chat_id: str, text: str) -> bool:
    url = TELEGRAM_SEND_URL
    payload = {"chat_id": chat_id, "text": text}
    try:
        r = requests.post(url, data=payload, timeout=15)
    except Exception as e:
        logger.warning("Telegram post failed (network): %s", e)
        return False

    try:
        jr = r.json()
    except Exception:
        logger.warning("Telegram response not JSON: %s", r.text[:200])
        return False

    if jr.get("ok"):
        return True

    # handle flood control
    code = jr.get("error_code")
    params = jr.get("parameters", {}) or {}
    if code == 429 and "retry_after" in params:
        wait = int(params["retry_after"])
        logger.warning("Telegram flood control: retry after %s sec", wait)
        time.sleep(wait + 1)
        return safe_send_telegram_once(chat_id, text)
    else:
        logger.warning("Telegram send failed: %s", jr)
        return False

def send_to_all_chats(text: str):
    for cid in CHAT_IDS_LIST:
        ok = safe_send_telegram_once(cid, text)
        # throttle between chats to reduce risk of flood
        time.sleep(0.25)
        if not ok:
            logger.debug("Failed to send to %s", cid)

# ---------------- startup: seed DB with existing rows (do not forward) ----------------
def seed_existing_rows_to_db():
    """
    At startup, fetch recent rows and insert to DB without forwarding,
    so we don't forward old backlog. This marks messages as seen.
    """
    logger.info("Seeding DB with recent existing rows (no forward)...")
    rows = fetch_data_rows()
    if not rows:
        logger.info("No rows to seed (or fetch failed).")
        return
    for r in rows:
        entry = parse_row_to_entry(r)
        if not entry:
            continue
        try:
            if mongo_coll:
                mongo_coll.insert_one(entry)
        except errors.DuplicateKeyError:
            pass
        seen.add(entry["id"])
    save_seen_atomic(seen)
    logger.info("Seeding complete: %d items added/marked seen.", len(rows))

# ---------------- main loop ----------------
def main():
    if not BOT_TOKEN or not CHAT_IDS_LIST:
        logger.error("BOT_TOKEN or CHAT_IDS not set. Exiting.")
        return

    # initial login (will try cookies then credentials)
    create_session_and_login(force=True)

    # Seed DB with existing recent rows so we don't forward old ones
    seed_existing_rows_to_db()

    logger.info("Watching for new OTPs (live). Poll interval: %ss", POLL_INTERVAL)
    while True:
        rows = fetch_data_rows()
        if rows:
            # process chronological: oldest first
            for r in reversed(rows):
                entry = parse_row_to_entry(r)
                if not entry:
                    continue
                uid = entry["id"]
                if uid in seen:
                    continue
                # attempt to insert into Mongo (unique key prevents duplicates)
                inserted = False
                if mongo_coll:
                    try:
                        mongo_coll.insert_one(entry)
                        inserted = True
                    except errors.DuplicateKeyError:
                        # duplicate in DB -> skip and mark seen
                        seen.add(uid); save_seen_atomic(seen)
                        continue
                    except Exception as e:
                        logger.warning("Mongo insert error: %s", e)
                        # fallback: still forward only if not in local seen
                # If no mongo or inserted in mongo, decide to forward
                if entry.get("code") in (None, "N/A") and not FORWARD_IF_NO_CODE:
                    # still mark seen so won't try again
                    seen.add(uid); save_seen_atomic(seen)
                    continue
                # mark seen before sending to avoid duplicates on crash
                seen.add(uid); save_seen_atomic(seen)
                text = format_message(entry)
                logger.info("Forwarding OTP id=%s number=%s code=%s", uid[:8], entry.get("number"), entry.get("code"))
                send_to_all_chats(text)
        # small sleep
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
