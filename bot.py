#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Heroku-ready IMS SMS OTP Forwarder
- No duplicate resend (even after restart)
- MongoDB dedupe + local JSON fallback
- Auto session handling & stable polling
"""

import os, time, json, logging, re, tempfile, requests
from hashlib import sha1
from datetime import datetime, timedelta, timezone
from bs4 import BeautifulSoup
from pymongo import MongoClient

# === CONFIG ===
BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_IDS = os.getenv("CHAT_IDS", "")
USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")
SITE_BASE = os.getenv("SITE_BASE", "http://45.82.67.20").rstrip("/")
MONGO_URI = os.getenv("MONGO_URI", "")
POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "2"))
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "15"))
STATE_FILE = "seen.json"

LOGIN_URL = f"{SITE_BASE}/"
SIGNIN_URL = f"{SITE_BASE}/ints/signin"
DATA_API_URL = f"{SITE_BASE}/ints/agent/res/data_smscdr.php"
DASH_URL = f"{SITE_BASE}/ints/agent/SMSCDRStats"

CHAT_IDS_LIST = [c.strip() for c in CHAT_IDS.split(",") if c.strip()]
TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

# === LOGGING ===
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
log = logging.getLogger("OTP-Bot")

# === REGEX ===
OTP_CODE = re.compile(r'\b\d{3,8}\b')

# === MongoDB ===
mongo_coll = None
if MONGO_URI:
    try:
        client = MongoClient(MONGO_URI)
        db = client["otpdb"]
        mongo_coll = db["otps"]
        mongo_coll.create_index("id", unique=True)
        log.info("✅ MongoDB connected")
    except Exception as e:
        log.error("MongoDB connect fail: %s", e)

# === Seen cache ===
def load_seen():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                return set(json.load(f))
        except Exception:
            return set()
    return set()

def save_seen(seen):
    try:
        fd, tmp = tempfile.mkstemp()
        with os.fdopen(fd, "w") as f:
            json.dump(list(seen), f)
        os.replace(tmp, STATE_FILE)
    except Exception:
        pass

seen = load_seen()

# === Session login ===
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0"})

def login():
    try:
        r = session.get(LOGIN_URL, timeout=REQUEST_TIMEOUT)
        soup = BeautifulSoup(r.text, "html.parser")
        token = soup.find("input", {"name": "_token"})
        payload = {"username": USERNAME, "password": PASSWORD}
        if token:
            payload["_token"] = token.get("value")
        session.post(SIGNIN_URL, data=payload, timeout=REQUEST_TIMEOUT)
        log.info("✅ Login success")
    except Exception as e:
        log.error("Login fail: %s", e)

# === Telegram ===
def send_tg(text):
    for cid in CHAT_IDS_LIST:
        try:
            requests.post(TELEGRAM_API, data={"chat_id": cid, "text": text[:4000]}, timeout=10)
        except Exception:
            pass

# === Fetch SMS ===
def fetch_sms():
    now = datetime.now(timezone.utc)
    f1 = (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    f2 = now.strftime("%Y-%m-%d %H:%M:%S")
    try:
        r = session.get(DATA_API_URL, params={"fdate1": f1, "fdate2": f2}, timeout=REQUEST_TIMEOUT)
        if r.text.startswith("<"):
            login()
            return []
        data = r.json().get("aaData", [])
        return data
    except Exception as e:
        log.warning("Fetch fail: %s", e)
        return []

# === Parse ===
def parse_row(row):
    try:
        ts, operator, number, service, client, msg = row[:6]
    except Exception:
        return None
    uid = sha1(f"{number}|{msg}|{ts}".encode()).hexdigest()
    m = OTP_CODE.search(msg or "")
    code = m.group(0) if m else "N/A"
    return {
        "id": uid,
        "number": number.strip(),
        "msg": msg.strip(),
        "time": ts,
        "operator": operator or "Unknown",
        "code": code
    }

def format_msg(e):
    return (
        f"✅ New OTP Received\n\n"
        f"🕰️ Time: {e['time']}\n"
        f"📞 Number: {e['number']}\n"
        f"🔑 OTP Code: {e['code']}\n"
        f"🌍 Country: {e['operator']}\n\n"
        f"💬 Full Message:\n{e['msg']}"
    )

# === Main Loop ===
def main():
    if not BOT_TOKEN or not CHAT_IDS_LIST:
        log.error("Missing BOT_TOKEN or CHAT_IDS")
        return
    login()
    log.info("🚀 Bot started polling")
    while True:
        rows = fetch_sms()
        for row in reversed(rows):
            e = parse_row(row)
            if not e:
                continue
            if e["id"] in seen:
                continue
            if mongo_coll and mongo_coll.find_one({"id": e["id"]}):
                seen.add(e["id"])
                continue
            text = format_msg(e)
            send_tg(text)
            seen.add(e["id"])
            if mongo_coll:
                try:
                    mongo_coll.insert_one(e)
                except Exception:
                    pass
            save_seen(seen)
            log.info("Forwarded %s (%s)", e["number"], e["code"])
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
