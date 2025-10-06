#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IMS SMS Forwarder - FINAL WORKING VERSION
Fixed file saving and data filtering
"""

import os
import time
import json
import logging
import re
from hashlib import sha1
from datetime import datetime, timezone, timedelta
from urllib.parse import urljoin

import requests

# --- config ---
BASE_URL = os.getenv("BASE_URL", "https://imssms.org").rstrip("/")
DATA_API_PATH = os.getenv("IMSSMS_DATA_API_PATH", "/client/res/data_smscdr.php")
DATA_URL = urljoin(BASE_URL, DATA_API_PATH)

BOT_TOKEN = os.getenv("IMSSMS_BOT_TOKEN") or os.getenv("BOT_TOKEN")
CHAT_IDS_RAW = os.getenv("IMSSMS_CHAT_IDS") or os.getenv("CHAT_ID") or os.getenv("CHAT_IDS", "")
CHAT_IDS = [c.strip() for c in CHAT_IDS_RAW.split(",") if c.strip()]

# Manual session cookie - GET THIS FROM YOUR BROWSER
MANUAL_SESSION = os.getenv("MANUAL_SESSION") or os.getenv("PHPSESSID")

POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "15"))

# --- logging ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger("imssms-final")

# --- session ---
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "application/json, text/javascript, */*; q=0.01",
})

# Set manual session cookie if provided
if MANUAL_SESSION:
    session.cookies.set("PHPSESSID", MANUAL_SESSION)
    log.info("Using manual session cookie: %s...", MANUAL_SESSION[:20])

# regex
OTP_RE = re.compile(r"\b\d{3,8}\b")
TIMESTAMP_RE = re.compile(r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}')

# In-memory seen storage (Heroku has ephemeral filesystem)
seen_messages = set()

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
            else:
                log.info("✅ Telegram message sent successfully")
        except Exception as e:
            log.warning("Telegram send exception: %s", e)

# --- Fetch SMS with manual session ---
def fetch_sms(minutes_back=15):
    try:
        now = datetime.now(timezone.utc)
        f1 = (now - timedelta(minutes=minutes_back)).strftime("%Y-%m-%d %H:%M:%S")
        f2 = now.strftime("%Y-%m-%d %H:%M:%S")
        
        # Exact parameters from successful API call
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
            "mDataProp_0": "0",
            "sSearch_0": "",
            "bRegex_0": "false",
            "bSearchable_0": "true",
            "bSortable_0": "true",
            "mDataProp_1": "1",
            "sSearch_1": "",
            "bRegex_1": "false",
            "bSearchable_1": "true",
            "bSortable_1": "true",
            "mDataProp_2": "2",
            "sSearch_2": "",
            "bRegex_2": "false",
            "bSearchable_2": "true",
            "bSortable_2": "true",
            "mDataProp_3": "3",
            "sSearch_3": "",
            "bRegex_3": "false",
            "bSearchable_3": "true",
            "bSortable_3": "true",
            "mDataProp_4": "4",
            "sSearch_4": "",
            "bRegex_4": "false",
            "bSearchable_4": "true",
            "bSortable_4": "true",
            "mDataProp_5": "5",
            "sSearch_5": "",
            "bRegex_5": "false",
            "bSearchable_5": "true",
            "bSortable_5": "true",
            "mDataProp_6": "6",
            "sSearch_6": "",
            "bRegex_6": "false",
            "bSearchable_6": "true",
            "bSortable_6": "true",
            "sSearch": "",
            "bRegex": "false",
            "iSortCol_0": "0",
            "sSortDir_0": "desc",
            "iSortingCols": "1",
            "_": str(int(time.time() * 1000)),
        }
        
        headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"{BASE_URL}/client/SMSDashboard",
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
        }

        log.info("📡 Fetching SMS data from last %d minutes", minutes_back)
        r = session.get(DATA_URL, params=params, headers=headers, timeout=20)
        
        log.info("📊 Fetch status: %d", r.status_code)
        
        if r.status_code != 200:
            log.warning("❌ Fetch failed with status: %d", r.status_code)
            return "SESSION_EXPIRED"
            
        # Parse JSON response
        try:
            data = r.json()
            if isinstance(data, dict) and "aaData" in data:
                # Filter out footer rows and invalid data
                valid_sms = []
                for row in data["aaData"]:
                    if (isinstance(row, list) and len(row) >= 5 and 
                        isinstance(row[0], str) and TIMESTAMP_RE.match(row[0]) and
                        isinstance(row[2], str) and len(row[2]) > 5):  # Valid phone number
                        valid_sms.append(row)
                    else:
                        log.debug("Skipping invalid row: %s", row)
                
                log.info("✅ SUCCESS! Got %d valid SMS records", len(valid_sms))
                return valid_sms
            else:
                log.warning("Unexpected JSON structure: %s", list(data.keys()) if isinstance(data, dict) else type(data))
                return []
        except json.JSONDecodeError as e:
            log.error("❌ JSON parse failed: %s", e)
            # Check if we got HTML instead
            if r.text.strip().startswith('<!DOCTYPE html>') or r.text.strip().startswith('<html'):
                log.error("🔐 Got HTML instead of JSON - session expired")
                return "SESSION_EXPIRED"
            return []
            
    except Exception as e:
        log.exception("💥 Fetch exception: %s", e)
        return "SESSION_EXPIRED"

# --- Forwarding with proper filtering ---
def format_and_forward(row):
    try:
        ts = row[0] if len(row) > 0 else ""
        operator = row[1] if len(row) > 1 else ""
        number = row[2] if len(row) > 2 else ""
        service = row[3] if len(row) > 3 else ""
        message = row[4] if len(row) > 4 else ""
        
        # Skip if essential data is missing
        if not ts or not number or not message:
            log.debug("Skipping row with missing data: %s", row)
            return
            
        # Skip footer rows and invalid data
        if not TIMESTAMP_RE.match(ts) or len(number) < 5:
            log.debug("Skipping invalid row: %s", row)
            return
            
    except Exception as e:
        log.warning("Malformed row: %s - %s", row, e)
        return

    # Create unique ID for deduplication
    message_id = sha1(f"{ts}|{number}|{message}".encode()).hexdigest()
    
    if message_id in seen_messages:
        log.debug("Skipping duplicate message: %s", number)
        return
        
    # Extract OTP from message
    otps = OTP_RE.findall(message or "")
    otp = otps[-1] if otps else "N/A"
    
    # Format Telegram message
    text = (
        f"✅ *New OTP Received* ✅\n\n"
        f"🕰 *Time:* `{ts}`\n"
        f"📞 *Number:* `{number}`\n"
        f"🔢 *OTP Code:* `{otp}`\n"
        f"🌍 *Operator:* {operator}\n"
        f"📱 *Service:* {service}\n\n"
        f"💬 *Message:*\n`{message}`\n\n"
        f"🔗 *Source:* {BASE_URL}"
    )
    
    send_telegram(text)
    seen_messages.add(message_id)
    log.info("📤 Forwarded OTP from %s: %s", number, otp)

# --- Main loop ---
def main_loop():
    if not BOT_TOKEN or not CHAT_IDS:
        log.error("❌ Missing BOT_TOKEN or CHAT_IDS")
        return
        
    if not MANUAL_SESSION:
        log.error("❌ MANUAL_SESSION not set. Please get PHPSESSID from browser.")
        log.error("💡 How to get: Login in browser → F12 → Application → Cookies → Copy PHPSESSID")
        return

    log.info("🚀 Starting IMS SMS Forwarder")
    log.info("📞 Monitoring for new OTP messages...")
    
    consecutive_failures = 0
    max_failures = 3
    
    while True:
        try:
            result = fetch_sms(minutes_back=30)  # Increased to 30 minutes for better coverage
            
            if result == "SESSION_EXPIRED":
                consecutive_failures += 1
                log.error("🔐 Session expired (%d/%d)", consecutive_failures, max_failures)
                
                if consecutive_failures >= max_failures:
                    log.error("❌ Manual session expired. Please update MANUAL_SESSION config var.")
                    log.error("💡 Get new PHPSESSID from browser and run: heroku config:set MANUAL_SESSION=new_value")
                    time.sleep(300)  # Wait 5 minutes before retrying
                    consecutive_failures = 0
                else:
                    time.sleep(60)
                continue
                
            # Reset failure counter on success
            consecutive_failures = 0
            
            # Process SMS records
            if result and isinstance(result, list):
                valid_count = 0
                for row in result:
                    if isinstance(row, list):
                        format_and_forward(row)
                        valid_count += 1
                
                if valid_count > 0:
                    log.info("📨 Processed %d new SMS messages", valid_count)
                else:
                    log.info("⏳ No new OTP messages found")
            else:
                log.info("⏳ No SMS data received")
            
            time.sleep(POLL_INTERVAL)
                
        except KeyboardInterrupt:
            log.info("⏹️ Interrupted by user")
            break
        except Exception:
            log.exception("💥 Main loop error - restarting in 30s")
            time.sleep(30)

if __name__ == "__main__":
    main_loop()
