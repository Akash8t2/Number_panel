#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IMS SMS OTP Forwarder with MongoDB + Telegram
- Only forwards NEW OTPs (no duplicates, no old history)
- Saves all OTPs to MongoDB
- Handles session reuse (no infinite login)
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
USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")

MONGO_URI = os.getenv("MONGO_URI", "mongodb+srv://BrandedSupportGroup:BRANDED_WORLD@cluster0.v4odcq9.mongodb.net/?retryWrites=true&w=majority")
MONGO_DB = os.getenv("MONGO_DB", "otp_forwarder")
MONGO_COLL = os.getenv("MONGO_COLL", "otps")

SITE_BASE = os.getenv("SITE_BASE", "http://45.82.67.20").rstrip("/")
LOGIN_PATH = "/ints/login"
SIGNIN_PATH = "/ints/signin"
DASH_PATH = "/ints/agent/SMSCDRStats"
DATA_API_PATH = "/ints/agent/res/data_smscdr.php"

POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "2"))
STATE_FILE = os.getenv("STATE_FILE", "processed_sms_ids.json")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "15"))
USER_AGENT = os.getenv("USER_AGENT", "Mozilla/5.0 (X11; Linux x86_64)")

LOGIN_URL = urljoin(SITE_BASE + "/", LOGIN_PATH.lstrip("/"))
SIGNIN_URL = urljoin(SITE_BASE + "/", SIGNIN_PATH.lstrip("/"))
DASH_URL = urljoin(SITE_BASE + "/", DASH_PATH.lstrip("/"))
DATA_API_URL = urljoin(SITE_BASE + "/", DATA_API_PATH.lstrip("/"))

CHAT_IDS_LIST = [c.strip() for c in (CHAT_IDS or "").split(",") if c.strip()]
TELEGRAM_SEND_URL = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

# Regex for OTP
OTP_HYPH = re.compile(r'(\d{3}-\d{3})')
OTP_PLAIN = re.compile(r'\b(\d{4,8})\b')

# Logging
logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s", level=logging.INFO)
logger = logging.getLogger("otp_forwarder")

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

# ---------------- MONGO ----------------
try:
    mongo_client = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
    mongo_db = mongo_client[MONGO_DB]
    mongo_coll = mongo_db[MONGO_COLL]
    mongo_client.admin.command("ping")
    logger.info("✅ MongoDB connected")
except Exception as e:
    logger.error("❌ MongoDB connection failed: %s", e)
    mongo_coll = None

# ---------------- SESSION ----------------
session: Optional[requests.Session] = None

def create_session_and_login(force: bool = False) -> Optional[requests.Session]:
    global session
    if session and not force:
        return session

    if not USERNAME or not PASSWORD:
        logger.error("USERNAME or PASSWORD missing.")
        return None

    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT})

    try:
        r = s.get(LOGIN_URL, timeout=REQUEST_TIMEOUT)
        soup = BeautifulSoup(r.text or "", "html.parser")
        token_input = soup.find("input", {"name": "_token"})
        payload = {"username": USERNAME, "password": PASSWORD}
        if token_input:
            payload[token_input.get("name")] = token_input.get("value")

        s.post(SIGNIN_URL, data=payload, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        dash_resp = s.get(DASH_URL, timeout=REQUEST_TIMEOUT)
        if dash_resp.status_code == 200:
            session = s
            logger.info("✅ Session login successful")
            return session
        else:
            logger.error("❌ Dashboard access failed after login")
            return None
    except Exception as e:
        logger.error("Login error: %s", e)
        return None

# ---------------- TELEGRAM ----------------
def _safe_send_telegram(chat_id: str, text: str):
    try:
        r = requests.post(TELEGRAM_SEND_URL, data={"chat_id": chat_id, "text": text}, timeout=10)
        if r.status_code != 200:
            logger.warning("Telegram send error: %s", r.text[:100])
    except Exception as e:
        logger.warning("Telegram send failed: %s", e)

def send_to_all_chats_and_commit(text: str, entry: dict):
    for cid in CHAT_IDS_LIST:
        _safe_send_telegram(cid, text)
        time.sleep(0.2)
    if mongo_coll:
        try:
            mongo_coll.update_one({"id": entry["id"]}, {"$set": entry}, upsert=True)
        except Exception as e:
            logger.warning("Mongo insert failed: %s", e)
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
    fdate1 = (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")

    params = {
        "fdate1": fdate1,
        "fdate2": fdate2,
        "iDisplayStart": "0",
        "iDisplayLength": "50"
    }

    try:
        r = session.get(DATA_API_URL, params=params, timeout=REQUEST_TIMEOUT)
        if r.status_code == 401 or r.text.strip().startswith("<"):
            logger.warning("⚠️ Session expired, re-logging in...")
            session = create_session_and_login(force=True)
            return None
        return r.json().get("aaData", [])
    except Exception as e:
        logger.warning("Fetch failed: %s", e)
        session = None
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
        "code": code, "code_plain": code_plain,
        "inserted_at": datetime.utcnow()
    }

def format_message(entry: dict) -> str:
    return (
        "🔔 Live OTP received\n\n"
        f"📞 Number: {entry.get('number','N/A')}\n"
        f"🔑 Code: {entry.get('code','N/A')}\n"
        f"🏆 Service: {entry.get('service','Unknown')}\n"
        f"🌎 Country: {entry.get('operator','Unknown')}\n"
        f"⏳ Time: {entry.get('time')}\n\n"
        f"💬 Message:\n{entry.get('message','')}"
    )

# ---------------- MAIN ----------------
def main():
    if not BOT_TOKEN or not CHAT_IDS_LIST:
        logger.error("BOT_TOKEN or CHAT_IDS missing.")
        return

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
                seen.add(uid)
                text = format_message(entry)
                logger.info("Forwarding OTP %s -> %s", entry["number"], entry["code"])
                send_to_all_chats_and_commit(text, entry)
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
