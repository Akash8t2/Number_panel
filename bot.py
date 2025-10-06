#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IMS SMS Forwarder - UPDATED VERSION
Country flags and live OTP filtering
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
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("imssms-bot")

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

# OTP regex patterns (ordered by priority)
OTP_PATTERNS = [
    r'\b\d{3}-\d{3}\b',      # 295-055 (most common)
    r'\b\d{6}\b',            # 295055
    r'\b\d{3}\s\d{3}\b',     # 295 055
    r'\b\d{3,8}\b',          # fallback: any 3-8 digit number
]

# Country mapping from operator names
COUNTRY_FLAGS = {
    # Venezuela
    "venezuela": "🇻🇪 Venezuela",
    "movilnet": "🇻🇪 Venezuela",
    
    # Italy
    "italy": "🇮🇹 Italy", 
    "wind": "🇮🇹 Italy",
    "heg": "🇮🇹 Italy",
    
    # Kazakhstan
    "kazakhstan": "🇰🇿 Kazakhstan",
    
    # Kyrgyzstan
    "kyrgyzstan": "🇰🇬 Kyrgyzstan",
    
    # Togo
    "togo": "🇹🇬 Togo",
    
    # Default fallbacks
    "default": "🌍 Unknown"
}

# In-memory seen storage (Heroku has ephemeral filesystem)
seen_messages = set()

# --- Telegram send ---
def send_telegram(msg: str):
    """Send message to Telegram"""
    if not BOT_TOKEN or not CHAT_IDS:
        log.warning("Telegram token or chat ids missing; skipping send")
        return False
    
    url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
    success = True
    
    for cid in CHAT_IDS:
        try:
            resp = requests.post(
                url, 
                data={
                    "chat_id": cid, 
                    "text": msg, 
                    "parse_mode": "Markdown",
                    "disable_web_page_preview": True
                }, 
                timeout=10
            )
            if resp.status_code != 200:
                log.warning("Telegram send failure %s: %s", resp.status_code, resp.text[:200])
                success = False
            else:
                log.debug("✅ Telegram message sent to chat %s", cid)
        except Exception as e:
            log.warning("Telegram send exception: %s", e)
            success = False
    
    return success

# --- Extract OTP from message ---
def extract_otp(message: str) -> str:
    """Extract OTP code from message using multiple patterns"""
    if not message:
        return "N/A"
    
    for pattern in OTP_PATTERNS:
        matches = re.findall(pattern, message)
        if matches:
            # Return the last match (most likely the OTP)
            return matches[-1]
    
    return "N/A"

# --- Map operator to country with flag ---
def get_country_from_operator(operator: str) -> str:
    """Convert operator name to country with flag"""
    if not operator:
        return COUNTRY_FLAGS["default"]
    
    operator_lower = operator.lower()
    
    # Check for country matches
    for country_key, country_value in COUNTRY_FLAGS.items():
        if country_key in operator_lower and country_key != "default":
            return country_value
    
    # Default fallback
    return COUNTRY_FLAGS["default"]

# --- Check if SMS is recent (within 10 minutes) ---
def is_recent_sms(timestamp_str: str, max_minutes_ago: int = 10) -> bool:
    """Check if SMS timestamp is within the last max_minutes_ago minutes"""
    try:
        # Parse the timestamp (format: "2025-10-06 15:48:42")
        sms_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        current_time = datetime.now()
        
        # Calculate time difference
        time_diff = current_time - sms_time
        time_diff_minutes = time_diff.total_seconds() / 60
        
        # Return True if within the allowed time window
        return time_diff_minutes <= max_minutes_ago
        
    except Exception as e:
        log.warning("Failed to parse timestamp '%s': %s", timestamp_str, e)
        return False  # If we can't parse, assume it's not recent

# --- Fetch SMS with comprehensive data detection ---
def fetch_sms(minutes_back=10):  # Reduced to 10 minutes for live OTPs only
    """Fetch SMS data from IMS SMS API"""
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

        log.info("📡 Fetching LIVE SMS data from last %d minutes", minutes_back)
        r = session.get(DATA_URL, params=params, headers=headers, timeout=20)
        
        log.info("📊 API Response: %d %s", r.status_code, r.reason)
        
        if r.status_code != 200:
            log.warning("❌ Fetch failed with status: %d", r.status_code)
            return "SESSION_EXPIRED"
            
        # Parse JSON response
        try:
            data = r.json()
            if isinstance(data, dict) and "aaData" in data:
                raw_rows = len(data["aaData"])
                log.info("📦 Received %d raw data rows", raw_rows)
                
                # Filter valid SMS rows
                valid_sms = []
                for i, row in enumerate(data["aaData"]):
                    if isinstance(row, list) and len(row) >= 5:
                        timestamp = str(row[0]) if len(row) > 0 else ""
                        number = str(row[2]) if len(row) > 2 else ""
                        message = str(row[4]) if len(row) > 4 else ""
                        
                        # Skip footer rows and invalid data
                        if (number and not number.startswith("0,0,0") and 
                            message and len(number) >= 3):
                            
                            # Check if SMS is recent (within 10 minutes)
                            if is_recent_sms(timestamp, max_minutes_ago=10):
                                valid_sms.append(row)
                            else:
                                log.debug("Skipping old SMS from %s: %s", number, timestamp)
                        else:
                            log.debug("Skipping invalid row %d: %s", i, row[:3])
                    else:
                        log.debug("Skipping malformed row %d: %s", i, row)
                
                log.info("✅ Found %d LIVE SMS records (last 10 minutes)", len(valid_sms))
                
                # Log sample for debugging
                if valid_sms:
                    sample = valid_sms[0]
                    log.info("📝 Live Sample: %s | %s | %s", 
                            sample[0] if len(sample) > 0 else "N/A",
                            sample[2] if len(sample) > 2 else "N/A", 
                            (sample[4][:80] + "...") if len(sample) > 4 and len(sample[4]) > 80 else 
                            sample[4] if len(sample) > 4 else "N/A")
                
                return valid_sms
            else:
                log.warning("Unexpected JSON structure in response")
                return []
                
        except json.JSONDecodeError as e:
            log.error("❌ JSON parse failed: %s", e)
            # Check if we got HTML instead (session expired)
            if r.text.strip().startswith(('<!DOCTYPE html>', '<html')):
                log.error("🔐 Session expired - got HTML login page")
                return "SESSION_EXPIRED"
            log.debug("Raw response: %s", r.text[:500])
            return []
            
    except requests.exceptions.RequestException as e:
        log.error("🌐 Network error: %s", e)
        return "NETWORK_ERROR"
    except Exception as e:
        log.exception("💥 Unexpected error in fetch_sms: %s", e)
        return "ERROR"

# --- Process and forward SMS ---
def process_sms(row):
    """Process a single SMS row and forward to Telegram"""
    try:
        # Extract data from row
        ts = str(row[0]) if len(row) > 0 else "Unknown"
        operator = str(row[1]) if len(row) > 1 else "Unknown"
        number = str(row[2]) if len(row) > 2 else "Unknown"
        service = str(row[3]) if len(row) > 3 else "Unknown"
        message = str(row[4]) if len(row) > 4 else ""
        
        # Validate essential fields
        if not number or number.startswith("0,0,0") or not message:
            log.debug("Skipping invalid SMS row")
            return False
            
        # Double-check timestamp is recent
        if not is_recent_sms(ts, max_minutes_ago=10):
            log.debug("Skipping old message from %s: %s", number, ts)
            return False
            
    except Exception as e:
        log.warning("Failed to parse SMS row: %s - %s", row, e)
        return False

    # Create unique message ID for deduplication
    message_id = sha1(f"{ts}|{number}|{message}".encode()).hexdigest()
    
    # Check for duplicates
    if message_id in seen_messages:
        log.debug("Skipping duplicate message from %s", number)
        return False
        
    # Extract OTP code
    otp_code = extract_otp(message)
    
    # Get country with flag from operator
    country = get_country_from_operator(operator)
    
    # Format Telegram message (WITHOUT SOURCE)
    telegram_msg = (
        f"✅ *New OTP Received* ✅\n\n"
        f"🕰 *Time:* `{ts}`\n"
        f"📞 *Number:* `{number}`\n"
        f"🔢 *OTP Code:* `{otp_code}`\n"
        f"{country}\n"
        f"📱 *Service:* {service}\n\n"
        f"💬 *Message:*\n`{message}`"
    )
    
    # Send to Telegram
    if send_telegram(telegram_msg):
        seen_messages.add(message_id)
        log.info("📤 Forwarded LIVE OTP from %s: %s", number, otp_code)
        return True
    else:
        log.error("❌ Failed to send Telegram message for %s", number)
        return False

# --- Health check and session validation ---
def check_session_health():
    """Check if the current session is still valid"""
    try:
        test_params = {
            "fdate1": "2025-01-01 00:00:00",
            "fdate2": "2025-01-01 00:01:00",
            "sEcho": "1",
            "iDisplayStart": "0",
            "iDisplayLength": "1",
            "_": str(int(time.time() * 1000)),
        }
        
        r = session.get(DATA_URL, params=test_params, timeout=10)
        return r.status_code == 200 and "aaData" in r.json()
    except:
        return False

# --- Main loop ---
def main_loop():
    """Main application loop"""
    # Validate configuration
    if not BOT_TOKEN or not CHAT_IDS:
        log.error("❌ Missing required configuration: BOT_TOKEN or CHAT_IDS")
        return
        
    if not MANUAL_SESSION:
        log.error("❌ MANUAL_SESSION not configured")
        log.error("💡 How to setup:")
        log.error("1. Login to %s in your browser", BASE_URL)
        log.error("2. Press F12 → Application → Cookies → Copy PHPSESSID value")
        log.error("3. Run: heroku config:set MANUAL_SESSION=your_phpsessid_value")
        return

    log.info("🚀 Starting IMS SMS Forwarder - LIVE OTP MODE")
    log.info("📞 Monitoring for LIVE OTP messages (last 10 minutes only)")
    log.info("⏰ Polling interval: %d seconds", POLL_INTERVAL)
    log.info("👥 Telegram chats: %s", CHAT_IDS)
    
    # Initial session health check
    if not check_session_health():
        log.warning("⚠️ Initial session health check failed - proceeding anyway")
    
    consecutive_failures = 0
    max_consecutive_failures = 5
    
    while True:
        try:
            # Fetch SMS data (only last 10 minutes for live OTPs)
            result = fetch_sms(minutes_back=10)
            
            # Handle different result types
            if result in ["SESSION_EXPIRED", "NETWORK_ERROR", "ERROR"]:
                consecutive_failures += 1
                log.error("❌ Operation failed: %s (%d/%d)", 
                         result, consecutive_failures, max_consecutive_failures)
                
                if consecutive_failures >= max_consecutive_failures:
                    if result == "SESSION_EXPIRED":
                        log.error("🔐 Session expired. Please update MANUAL_SESSION:")
                        log.error("1. Login to %s in browser", BASE_URL)
                        log.error("2. Get new PHPSESSID from Developer Tools")
                        log.error("3. Run: heroku config:set MANUAL_SESSION=new_value")
                    time.sleep(300)  # Wait 5 minutes
                    consecutive_failures = 0
                else:
                    time.sleep(60)  # Wait 1 minute
                continue
                
            # Reset failure counter on success
            consecutive_failures = 0
            
            # Process SMS records
            if result and isinstance(result, list):
                processed_count = 0
                for sms_row in result:
                    if process_sms(sms_row):
                        processed_count += 1
                
                if processed_count > 0:
                    log.info("📨 Successfully processed %d LIVE OTP messages", processed_count)
                else:
                    log.info("⏳ No new LIVE OTP messages found")
            else:
                log.info("⏳ No LIVE SMS data to process")
            
            # Wait for next poll
            time.sleep(POLL_INTERVAL)
                
        except KeyboardInterrupt:
            log.info("⏹️ Application stopped by user")
            break
        except Exception as e:
            log.exception("💥 Unexpected error in main loop: %s", e)
            log.info("🔄 Restarting in 30 seconds...")
            time.sleep(30)

if __name__ == "__main__":
    main_loop()
