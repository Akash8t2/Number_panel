#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IMS SMS OTP Forwarder Bot
- Supports https://imssms.org/login
- Fetches SMS JSON safely
- Forwards to Telegram
- Optional MongoDB dedupe
- Heroku-ready
"""

import os
import time
import logging
import re
import requests
from datetime import datetime
from hashlib import sha1
from pymongo import MongoClient

# === CONFIG ===
BASE_URL = os.getenv("BASE_URL", "https://imssms.org")
LOGIN_URL = f"{BASE_URL}/login"
DATA_API = os.getenv("IMSSMS_DATA_API_PATH", "/client/res/data_smscdr.php")

USERNAME = os.getenv("IMS_USERNAME")
PASSWORD = os.getenv("IMS_PASSWORD")
BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")

MONGO_URI = os.getenv("MONGO_URI", "")
USE_MONGO = bool(MONGO_URI)

# === LOGGING ===
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")

# === SESSION ===
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (HerokuBot/1.0)",
    "X-Requested-With": "XMLHttpRequest",
    "Accept": "application/json, text/javascript, */*; q=0.01",
})

# === MONGO INIT ===
if USE_MONGO:
    try:
        mongo = MongoClient(MONGO_URI, serverSelectionTimeoutMS=3000)
        db = mongo["ims_bot"]
        sms_col = db["sms"]
        mongo.server_info()
        logging.info("✅ MongoDB connected")
    except Exception as e:
        logging.warning(f"MongoDB connect fail: {e}")
        USE_MONGO = False

# === TELEGRAM SEND ===
def send_telegram(msg: str):
    if not BOT_TOKEN or not CHAT_ID:
        return
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    try:
        requests.post(url, data={"chat_id": CHAT_ID, "text": msg})
    except Exception as e:
        logging.error(f"Telegram send fail: {e}")

# === LOGIN ===
def ims_login():
    if not USERNAME or not PASSWORD:
        logging.error("No USERNAME/PASSWORD set for IMS bot")
        return False
    try:
        resp = session.post(LOGIN_URL, data={
            "username": USERNAME,
            "password": PASSWORD
        }, allow_redirects=True)
        logging.info(f"✅ Login attempted (status {resp.status_code})")
        # Debug: print cookies
        logging.info(f"Cookies: {session.cookies.get_dict()}")
        return resp.status_code == 200
    except Exception as e:
        logging.error(f"Login error: {e}")
        return False

# === FETCH SMS ===
def fetch_sms():
    try:
        now = datetime.utcnow()
        start = now.strftime("%Y-%m-%d 00:00:00")
        end = now.strftime("%Y-%m-%d 23:59:59")
        url = f"{BASE_URL}{DATA_API}?fdate1={start}&fdate2={end}&sEcho=1&iDisplayLength=50"
        resp = session.get(url)
        logging.info(f"Fetch status: {resp.status_code}")
        logging.info(f"Fetch content (truncated): {resp.text[:200]}")
        if resp.status_code != 200:
            return []
        # Only parse JSON if it starts with {
        if resp.text.strip().startswith("{"):
            return resp.json().get("aaData", [])
        return []
    except Exception as e:
        logging.error(f"Fetch error: {e}")
        return []

# === DEDUPLICATE ===
seen = set()

def already_sent(msg_id):
    if USE_MONGO:
        return sms_col.find_one({"_id": msg_id})
    return msg_id in seen

def mark_sent(msg_id):
    if USE_MONGO:
        try:
            sms_col.insert_one({"_id": msg_id})
        except:
            pass
    else:
        seen.add(msg_id)

# === MAIN LOOP ===
def main():
    if not ims_login():
        logging.warning("Login failed. Retrying in 60s...")
        time.sleep(60)
        return

    logging.info(f"🚀 IMS bot started polling {BASE_URL} (api={DATA_API})")
    while True:
        try:
            for sms in fetch_sms():
                text = sms[3] if len(sms) > 3 else ""
                sender = sms[1] if len(sms) > 1 else ""
                date = sms[0] if len(sms) > 0 else ""
                msg_id = sha1(f"{sender}{text}{date}".encode()).hexdigest()

                if not already_sent(msg_id):
                    formatted = (
                        f"📩 *New SMS*\n"
                        f"From: `{sender}`\n"
                        f"Text: `{text}`\n"
                        f"Date: {date}"
                    )
                    send_telegram(formatted)
                    mark_sent(msg_id)
            time.sleep(20)
        except Exception as e:
            logging.error(f"Loop error: {e}")
            time.sleep(15)

# === RUN ===
if __name__ == "__main__":
    while True:
        try:
            main()
        except Exception as e:
            logging.error(f"Fatal error: {e}")
            time.sleep(30)
