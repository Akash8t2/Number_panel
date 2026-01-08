#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
NumberPanel OTP Bot
Mode: ONLY LATEST (NEW ONE) OTP
Website: http://51.89.99.105/NumberPanel
"""

import os
import time
import json
import re
import requests
from datetime import datetime

# ================= CONFIG =================
BASE_URL = os.getenv("BASE_URL", "http://51.89.99.105/NumberPanel").rstrip("/")
API_PATH = "/client/res/data_smscdr.php"

PHPSESSID = os.getenv("PHPSESSID", "PUT_YOUR_PHPSESSID_HERE")
BOT_TOKEN = os.getenv("BOT_TOKEN", "PUT_TELEGRAM_BOT_TOKEN_HERE")
CHAT_IDS = os.getenv("CHAT_IDS", "-1001234567890").split(",")

CHECK_INTERVAL = int(os.getenv("CHECK_INTERVAL", "10"))
STATE_FILE = "last_seen.json"

# ================= HEADERS =================
HEADERS = {
    "Accept": "application/json, text/javascript, */*; q=0.01",
    "X-Requested-With": "XMLHttpRequest",
    "User-Agent": "Mozilla/5.0",
    "Referer": f"{BASE_URL}/client/SMSDashboard",
}

# ================= SESSION =================
session = requests.Session()
session.cookies.set("PHPSESSID", PHPSESSID)

# ================= HELPERS =================
def load_last_seen():
    if os.path.exists(STATE_FILE):
        try:
            return json.load(open(STATE_FILE))
        except Exception:
            return {}
    return {}

def save_last_seen(data):
    json.dump(data, open(STATE_FILE, "w"))

def extract_otp(text):
    if not text:
        return None
    m = re.search(r"\b(\d{4,8})\b", text)
    return m.group(1) if m else None

def send_telegram(text):
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    for chat_id in CHAT_IDS:
        payload = {
            "chat_id": chat_id.strip(),
            "text": text,
            "parse_mode": "Markdown",
            "disable_web_page_preview": True
        }
        requests.post(url, json=payload, timeout=10)

# ================= START =================
print("🚀 NumberPanel OTP Bot Started")
print("⚡ Mode: ONLY LATEST OTP")

last_seen = load_last_seen()

while True:
    try:
        params = {
            "fdate1": "2025-01-01 00:00:00",
            "fdate2": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "iDisplayStart": 0,
            "iDisplayLength": 1,  # 🔥 ONLY LATEST ROW
            "sEcho": 1,
            "_": int(time.time() * 1000),
        }

        r = session.get(
            BASE_URL + API_PATH,
            headers=HEADERS,
            params=params,
            timeout=10
        )

        if r.status_code != 200:
            time.sleep(CHECK_INTERVAL)
            continue

        data = r.json()
        rows = data.get("aaData", [])

        if not rows:
            time.sleep(CHECK_INTERVAL)
            continue

        # ✅ ONLY FIRST (LATEST) SMS
        ts, pool, number, service, message = rows[0][:5]
        key = f"{number}_{ts}"

        if last_seen.get("last_key") == key:
            time.sleep(CHECK_INTERVAL)
            continue

        otp = extract_otp(message)

        if otp:
            msg = (
                f"🔐 *NEW OTP RECEIVED*\n"
                f"━━━━━━━━━━━━━━\n"
                f"🕒 `{ts}`\n"
                f"📞 `{number}`\n"
                f"📲 `{service}`\n"
                f"🔢 *OTP:* `{otp}`\n"
            )
            send_telegram(msg)

        # 🔒 Mark as processed (even if OTP not found)
        last_seen = {"last_key": key}
        save_last_seen(last_seen)

    except Exception as e:
        print("❌ Error:", e)

    time.sleep(CHECK_INTERVAL)
