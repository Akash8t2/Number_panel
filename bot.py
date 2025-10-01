#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Heroku-ready IMS SMS OTP forwarder
- Live fetch + dedupe
- MongoDB integration
- Config via environment variables
"""

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
from pymongo import MongoClient

# ---------------- CONFIG ----------------
BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_IDS = os.getenv("CHAT_IDS", "")
ADMIN_CHAT_IDS = os.getenv("ADMIN_CHAT_IDS", "")
USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")
MONGO_URI = os.getenv("MONGO_URI")  # e.g., mongodb+srv://user:pass@cluster0.mongodb.net/?retryWrites=true&w=majority

SITE_BASE = os.getenv("SITE_BASE", "http://45.82.67.20").rstrip("/")
LOGIN_PATH = "/ints/login"
SIGNIN_PATH = "/ints/signin"
DASH_PATH = "/ints/agent/SMSCDRStats"
DATA_API_PATH = "/ints/agent/res/data_smscdr.php"

POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "1"))
STATE_FILE = os.getenv("STATE_FILE", "processed_sms_ids.json")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "15"))
USER_AGENT = os.getenv("USER_AGENT", "Mozilla/5.0 (X11; Linux x86_64)")
FORWARD_IF_NO_CODE = os.getenv("FORWARD_IF_NO_CODE", "true").lower() in ("1", "true", "yes")

LOGIN_URL = urljoin(SITE_BASE + "/", LOGIN_PATH.lstrip("/"))
SIGNIN_URL = urljoin(SITE_BASE + "/", SIGNIN_PATH.lstrip("/"))
DASH_URL = urljoin(SITE_BASE + "/", DASH_PATH.lstrip("/"))
DATA_API_URL = urljoin(SITE_BASE + "/", DATA_API_PATH.lstrip("/"))

CHAT_IDS_LIST = [c.strip() for c in (CHAT_IDS or "").split(",") if c.strip()]
ADMIN_CHAT_IDS_LIST = [c.strip() for c in (ADMIN_CHAT_IDS or "").split(",") if c.strip()]
TELEGRAM_SEND_URL = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

COOKIES_RAW = os.getenv("COOKIES", "")  # optional "k=v; k2=v2"

# ---------------- LOGGING ----------------
logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s", level=logging.INFO)
logger = logging.getLogger("otp_forwarder")

# ---------------- REGEX ----------------
OTP_HYPH = re.compile(r'(\d{3}-\d{3})')
OTP_PLAIN = re.compile(r'\b(\d{3,8})\b')

# ---------------- MONGODB ----------------
mongo_client: Optional[MongoClient] = None
mongo_coll = None
if MONGO_URI:
    try:
        mongo_client = MongoClient(MONGO_URI)
        mongo_db = mongo_client.get_database("otpdb")
        mongo_coll = mongo_db.get_collection("otps")
        mongo_coll.create_index("id", unique=True)
        logger.info("✅ MongoDB connected and index ensured")
    except Exception as e:
        logger.error("MongoDB connection failed: %s", e)

# ---------------- STATE ----------------
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
    except Exception:
        pass

seen: Set[str] = load_seen()

# ---------------- SESSION ----------------
session: Optional[requests.Session] = None
_last_login_time = 0
LOGIN_MIN_INTERVAL = 2

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

def create_session_and_login(force: bool = False) -> Optional[requests.Session]:
    global session, _last_login_time
    now = time.time()
    if not force and session and now - _last_login_time < LOGIN_MIN_INTERVAL:
        return session
    _last_login_time = now

    if not USERNAME or not PASSWORD:
        logger.error("USERNAME or PASSWORD missing.")
        return None

    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})

    # try cookies first
    if INJECTED_COOKIES:
        try:
            s.cookies.update(INJECTED_COOKIES)
            chk = s.get(DASH_URL, timeout=REQUEST_TIMEOUT)
            if chk.status_code < 400 and "sms" in (chk.text or "").lower():
                session = s
                logger.info("✅ Session initialized from provided cookies.")
                return session
        except Exception:
            pass

    # login
    try:
        r = s.get(LOGIN_URL, timeout=REQUEST_TIMEOUT)
    except Exception:
        return None

    soup = BeautifulSoup(r.text or "", "html.parser")
    token_input = soup.find("input", {"name": "_token"})
    payload = {"username": USERNAME, "password": PASSWORD}
    if token_input:
        payload[token_input.get("name")] = token_input.get("value")

    try:
        s.post(SIGNIN_URL, data=payload, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    except Exception:
        return None

    try:
        s.get(DASH_URL, timeout=REQUEST_TIMEOUT)
    except Exception:
        pass

    session = s
    logger.info("✅ Session login successful")
    return session

# ---------------- TELEGRAM ----------------
def _safe_send_telegram(chat_id: str, text: str):
    try:
        r = requests.post(TELEGRAM_SEND_URL, data={"chat_id": chat_id, "text": text}, timeout=10)
        if r.status_code != 200:
            logger.warning("Telegram send error: %s", r.text[:100])
    except Exception as e:
        logger.warning("Telegram send failed: %s", e)

def send_to_all_chats_and_commit(text: str):
    for cid in CHAT_IDS_LIST:
        _safe_send_telegram(cid, text)
        time.sleep(0.1)
    save_seen_atomic(seen)

# ---------------- FETCH ----------------
def fetch_data_rows() -> Optional[list]:
    global session
    if session is None:
        session = create_session_and_login(force=True)
    if session is None:
        return None

    now = datetime.now(tz=timezone.utc)
    fdate2 = now.strftime("%Y-%m-%d %H:%M:%S")
    fdate1 = (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")  # last 5 min only

    params = {
        "fdate1": fdate1,
        "fdate2": fdate2,
        "iDisplayStart": "0",
        "iDisplayLength": "100"
    }

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest"
    }

    try:
        r = session.get(DATA_API_URL, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        if r.text.strip().startswith("<"):
            session = create_session_and_login(force=True)
            return None
        return r.json().get("aaData", [])
    except Exception as e:
        logger.warning("Fetch failed: %s", e)
        return None

# ---------------- PARSE ----------------
def parse_row_to_entry(row):
    try:
        ts, operator, number_raw, service_field, client, message_raw = row[:6]
    except Exception:
        return None

    number = str(number_raw or "").strip()
    message = str(message_raw or "")

    m = OTP_HYPH.search(message)
    if m:
        code = m.group(1)
        code_plain = code.replace("-", "")
    else:
        m2 = OTP_PLAIN.search(message)
        code = m2.group(1) if m2 else "N/A"
        code_plain = code

    uid = sha1(f"{number}|{message}|{ts}".encode()).hexdigest()
    service_guess = service_field if service_field not in ("", "0", "-") else "Unknown"

    return {
        "id": uid, "time": ts, "operator": operator,
        "number": number, "service": service_guess,
        "client": client, "message": message,
        "code": code, "code_plain": code_plain
    }

def format_message(entry: dict) -> str:
    number = str(entry.get("number", "N/A"))
    code = str(entry.get("code", "N/A"))
    service = str(entry.get("service", "Unknown"))
    country = str(entry.get("operator", "Unknown"))
    ts = str(entry.get("time", datetime.now(tz=timezone.utc).strftime("%Y-%m-%d %H:%M:%S")))
    msg = str(entry.get("message", ""))

    text = (
        "🔔 Live OTP received\n\n"
        f"📞 Number: {number}\n"
        f"🔑 Code: {code}\n"
        f"🏆 Service: {service}\n"
        f"🌎 Country: {country}\n"
        f"⏳ Time: {ts}\n\n"
        f"💬 Message:\n{msg}"
    )
    return text

# ---------------- DB SEED ----------------
def seed_existing_rows_to_db():
    global mongo_coll
    if mongo_coll is None:
        return
    rows = fetch_data_rows()
    if not rows:
        return
    for r in reversed(rows):
        entry = parse_row_to_entry(r)
        if not entry:
            continue
        uid = entry["id"]
        if mongo_coll.find_one({"id": uid}):
            continue
        mongo_coll.insert_one(entry)

# ---------------- MAIN ----------------
def main():
    if not BOT_TOKEN or not CHAT_IDS_LIST:
        logger.error("BOT_TOKEN or CHAT_IDS missing.")
        return

    # seed existing rows (no forward)
    seed_existing_rows_to_db()

    while True:
        rows = fetch_data_rows()
        if rows:
            for r in reversed(rows):
                entry = parse_row_to_entry(r)
                if not entry:
                    continue

                uid = entry["id"]
                if uid in seen:
                    continue

                if mongo_coll is not None and mongo_coll.find_one({"id": uid}):
                    seen.add(uid)
                    continue

                if (entry["code"] in (None, "N/A")) and not FORWARD_IF_NO_CODE:
                    seen.add(uid)
                    save_seen_atomic(seen)
                    continue

                # store in Mongo
                if mongo_coll is not None:
                    try:
                        mongo_coll.insert_one(entry)
                    except Exception:
                        pass

                seen.add(uid)
                text = format_message(entry)
                logger.info("Forwarding OTP %s -> %s", entry["number"], entry["code"])
                send_to_all_chats_and_commit(text)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
