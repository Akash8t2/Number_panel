#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IMS SMS Bot for https://imssms.org
----------------------------------
✅ Logs into imssms.org
✅ Polls /client/res/data_smscdr.php for SMS
✅ Extracts OTP codes & forwards to Telegram
✅ Dedupes via MongoDB or memory
✅ Auto-reconnects on session expiry
"""

import os
import time
import re
import json
import logging
from datetime import datetime, timedelta, timezone
import requests
from pymongo import MongoClient

# === Logging ===
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(message)s",
)
log = logging.getLogger()

# === ENV CONFIG ===
BOT_TOKEN = os.getenv("IMSSMS_BOT_TOKEN")
CHAT_IDS = [int(x) for x in os.getenv("IMSSMS_CHAT_IDS", "").split(",") if x.strip()]
IMS_USER = os.getenv("IMS_USER")
IMS_PASS = os.getenv("IMS_PASS")
DATA_PATH = os.getenv("IMSSMS_DATA_API_PATH", "/client/res/data_smscdr.php")
MONGO_URI = os.getenv("MONGO_URI")
BASE_URL = "https://imssms.org"

if not BOT_TOKEN or not CHAT_IDS:
    log.error("Missing BOT_TOKEN or CHAT_IDS — set IMSSMS_BOT_TOKEN and IMSSMS_CHAT_IDS (comma sep)")
    exit(0)

# === MongoDB Setup ===
seen = set()
if MONGO_URI:
    try:
        mongo = MongoClient(MONGO_URI, serverSelectionTimeoutMS=5000)
        db = mongo.imssms
        col = db.messages
        mongo.server_info()
        log.info("✅ MongoDB connected")
    except Exception as e:
        log.error("MongoDB connect fail: %s", e)
        mongo = None
else:
    mongo = None

# === Session Setup ===
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Linux; Android 12; IMSBot)"
})

OTP_RE = re.compile(r"\b\d{3,8}\b")


def telegram_send(msg: str):
    for cid in CHAT_IDS:
        try:
            requests.post(f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage", data={
                "chat_id": cid,
                "text": msg,
                "disable_web_page_preview": True,
            })
        except Exception as e:
            log.warning("TG send fail: %s", e)


def login():
    """Perform login to imssms.org"""
    try:
        r = session.post(
            f"{BASE_URL}/client/login",
            data={"username": IMS_USER, "password": IMS_PASS},
            timeout=15,
        )
        log.info("✅ Login attempted (status %s)", r.status_code)
        return r.status_code == 200
    except Exception as e:
        log.error("Login failed: %s", e)
        return False


def fetch_sms():
    """Fetch SMS JSON from imssms.org"""
    now = datetime.now(timezone.utc)
    f1 = (now - timedelta(hours=1)).strftime("%Y-%m-%d %H:%M:%S")
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
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
        "Cache-Control": "no-store, no-cache, must-revalidate",
        "Connection": "Keep-Alive",
    }

    try:
        r = session.get(f"{BASE_URL}{DATA_PATH}", params=params, headers=headers, timeout=15)
        if r.text.strip().startswith("<"):
            login()  # likely expired session
            return []
        data = r.json()
        return data.get("aaData", [])
    except Exception as e:
        log.warning("Fetch fail: %s", e)
        return []


def already_seen(entry_id: str) -> bool:
    if mongo:
        if col.find_one({"_id": entry_id}):
            return True
        col.insert_one({"_id": entry_id})
        return False
    else:
        if entry_id in seen:
            return True
        seen.add(entry_id)
        return False


def process_sms(rows):
    """Parse and forward new messages"""
    for row in rows:
        try:
            if len(row) < 5:
                continue
            timestamp, carrier, number, service, message = row[:5]
            entry_id = f"{timestamp}|{number}|{message.strip()}"

            if already_seen(entry_id):
                continue

            otps = OTP_RE.findall(message)
            otp_text = otps[-1] if otps else "N/A"

            text = (
                f"📱 *{service}*\n"
                f"👤 {number}\n"
                f"💬 {message.strip()}\n"
                f"⏰ {timestamp}\n"
                f"🔢 OTP: `{otp_text}`"
            )
            telegram_send(text)
            log.info("Forwarded %s", number)
        except Exception as e:
            log.warning("Process fail: %s", e)


def main_loop():
    login()
    log.info("🚀 IMS bot started polling %s (api=%s)", BASE_URL, DATA_PATH)
    while True:
        rows = fetch_sms()
        if rows:
            process_sms(rows)
        time.sleep(20)


if __name__ == "__main__":
    main_loop()
