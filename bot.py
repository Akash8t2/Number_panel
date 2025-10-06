#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NumberPanel OTP Sentinel - Secure OTP Forwarding
For http://51.89.99.105/NumberPanel
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

# --- config for new website ---
BASE_URL = os.getenv("BASE_URL", "http://51.89.99.105/NumberPanel").rstrip("/")
LOGIN_PATH = os.getenv("LOGIN_PATH", "/login")
DATA_API_PATH = os.getenv("DATA_API_PATH", "/client/res/data_smscdr.php")
LOGIN_URL = urljoin(BASE_URL, LOGIN_PATH)
DATA_URL = urljoin(BASE_URL, DATA_API_PATH)

BOT_TOKEN = os.getenv("BOT_TOKEN") or os.getenv("TELEGRAM_BOT_TOKEN")
CHAT_IDS_RAW = os.getenv("CHAT_IDS") or os.getenv("TELEGRAM_CHAT_IDS", "")
CHAT_IDS = [c.strip() for c in CHAT_IDS_RAW.split(",") if c.strip()]

# Manual session cookie - GET THIS FROM NEW WEBSITE
MANUAL_SESSION = os.getenv("MANUAL_SESSION") or os.getenv("PHPSESSID")

POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "15"))

# --- Bot Identity ---
BOT_NAME = "NumberPanel Sentinel"
BOT_USERNAME = "@NumberPanelBot"
BOT_TAGLINE = "🛡️ Guardian for Verification Codes"

# --- logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("numberpanel-bot")

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

# OTP regex patterns
OTP_PATTERNS = [
    r'\b\d{3}-\d{3}\b',      # 811-691 (most common)
    r'\b\d{4}\b',            # 2314 (for IMO)
    r'\b\d{6}\b',            # 811691
    r'\b\d{3}\s\d{3}\b',     # 811 691
    r'\b\d{3,8}\b',          # fallback
]

# Country mapping from operator names for NEW website
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
    
    # Add more based on your new website's operators
    "default": "🌍 Unknown"
}

# Service mapping
SERVICE_ICONS = {
    "whatsapp": "📱 WhatsApp",
    "imo": "💬 IMO", 
    "telegram": "✈️ Telegram",
    "facebook": "👥 Facebook",
    "google": "🔍 Google",
    "default": "📲 Unknown"
}

# In-memory seen storage
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
                log.debug("✅ Message delivered")
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
            return matches[-1]
    
    return "N/A"

# --- Map operator to country with flag ---
def get_country_from_operator(operator: str) -> str:
    """Convert operator name to country with flag"""
    if not operator:
        return COUNTRY_FLAGS["default"]
    
    operator_lower = operator.lower()
    
    for country_key, country_value in COUNTRY_FLAGS.items():
        if country_key in operator_lower and country_key != "default":
            return country_value
    
    return COUNTRY_FLAGS["default"]

# --- Map service to icon ---
def get_service_icon(service: str) -> str:
    """Convert service name to icon"""
    if not service:
        return SERVICE_ICONS["default"]
    
    service_lower = service.lower()
    
    for service_key, service_value in SERVICE_ICONS.items():
        if service_key in service_lower and service_key != "default":
            return service_value
    
    return SERVICE_ICONS["default"]

# --- Check if SMS is recent (within 10 minutes) ---
def is_recent_sms(timestamp_str: str, max_minutes_ago: int = 10) -> bool:
    """Check if SMS timestamp is within the last max_minutes_ago minutes"""
    try:
        sms_time = datetime.strptime(timestamp_str, "%Y-%m-%d %H:%M:%S")
        current_time = datetime.now()
        
        time_diff = current_time - sms_time
        time_diff_minutes = time_diff.total_seconds() / 60
        
        return time_diff_minutes <= max_minutes_ago
        
    except Exception as e:
        log.warning("Failed to parse timestamp '%s': %s", timestamp_str, e)
        return False

# --- Auto login for new website ---
def numberpanel_login(max_attempts=3):
    """Login to NumberPanel website"""
    username = os.getenv("NUMBERPANEL_USERNAME")
    password = os.getenv("NUMBERPANEL_PASSWORD")
    
    if not username or not password:
        log.info("No credentials provided, using manual session only")
        return True  # Continue with manual session
    
    for attempt in range(1, max_attempts + 1):
        try:
            log.info("🔐 Attempting login to NumberPanel (attempt %d)", attempt)
            r = session.get(LOGIN_URL, timeout=15)
            
            if r.status_code != 200:
                log.error("Login page failed: %s", r.status_code)
                continue
            
            # Parse login form
            from bs4 import BeautifulSoup
            soup = BeautifulSoup(r.text, "html.parser")
            form = soup.find("form")
            
            if not form:
                log.error("No login form found")
                continue
            
            action = form.get("action", "")
            action_url = urljoin(LOGIN_URL, action)
            
            # Extract form fields
            payload = {}
            for inp in form.find_all("input"):
                name = inp.get("name")
                value = inp.get("value", "")
                if name:
                    payload[name] = value
            
            # Set credentials
            payload["username"] = username
            payload["password"] = password
            
            # Login headers
            headers = {
                "Referer": LOGIN_URL,
                "Origin": BASE_URL,
                "Content-Type": "application/x-www-form-urlencoded",
            }
            
            log.info("📨 POST login to: %s", action_url)
            post = session.post(action_url, data=payload, headers=headers, allow_redirects=True, timeout=20)
            
            log.info("Login POST status: %s", post.status_code)
            log.info("Cookies after login: %s", session.cookies.get_dict())
            
            # Verify login
            dashboard_url = urljoin(BASE_URL, "/client/SMSDashboard")
            dash = session.get(dashboard_url, timeout=15)
            
            if dash.status_code == 200 and ("SMSDashboard" in dash.text or "Dashboard" in dash.text):
                log.info("✅ NumberPanel login successful!")
                return True
            else:
                log.warning("Dashboard verification failed")
                continue
                
        except Exception as e:
            log.exception("Login attempt %d failed: %s", attempt, e)
            time.sleep(5)
    
    log.error("All login attempts failed")
    return False

# --- Fetch SMS from new website ---
def fetch_sms(minutes_back=10):
    """Fetch SMS data from NumberPanel API"""
    try:
        now = datetime.now(timezone.utc)
        f1 = (now - timedelta(minutes=minutes_back)).strftime("%Y-%m-%d %H:%M:%S")
        f2 = now.strftime("%Y-%m-%d %H:%M:%S")
        
        # API parameters for NumberPanel
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
            "Referer": urljoin(BASE_URL, "/client/SMSDashboard"),
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
        }

        log.info("📡 Fetching from NumberPanel (%s to %s)", f1, f2)
        r = session.get(DATA_URL, params=params, headers=headers, timeout=20)
        
        log.info("📊 API Response: %d", r.status_code)
        
        if r.status_code != 200:
            log.warning("❌ Fetch failed: %d", r.status_code)
            return "SESSION_EXPIRED"
            
        # Parse JSON response
        try:
            data = r.json()
            if isinstance(data, dict) and "aaData" in data:
                raw_rows = len(data["aaData"])
                log.info("📦 Received %d messages", raw_rows)
                
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
                            
                            if is_recent_sms(timestamp, max_minutes_ago=10):
                                valid_sms.append(row)
                            else:
                                log.debug("Skipping old message: %s", timestamp)
                        else:
                            log.debug("Skipping invalid row")
                    else:
                        log.debug("Skipping malformed row")
                
                log.info("✅ %d live OTPs found", len(valid_sms))
                
                if valid_sms:
                    sample = valid_sms[0]
                    log.info("👀 Sample: %s | %s", 
                            sample[2] if len(sample) > 2 else "N/A", 
                            (sample[4][:60] + "...") if len(sample) > 4 and len(sample[4]) > 60 else sample[4] if len(sample) > 4 else "N/A")
                
                return valid_sms
            else:
                log.warning("Unexpected API response")
                return []
                
        except json.JSONDecodeError as e:
            log.error("❌ JSON parse failed: %s", e)
            if r.text.strip().startswith(('<!DOCTYPE html>', '<html')):
                log.error("🔐 Session expired")
                return "SESSION_EXPIRED"
            log.debug("Response: %s", r.text[:300])
            return []
            
    except requests.exceptions.RequestException as e:
        log.error("🌐 Network error: %s", e)
        return "NETWORK_ERROR"
    except Exception as e:
        log.exception("💥 Error: %s", e)
        return "ERROR"

# --- Process and forward SMS ---
def process_sms(row):
    """Process a single SMS row and forward to Telegram"""
    try:
        ts = str(row[0]) if len(row) > 0 else "Unknown"
        operator = str(row[1]) if len(row) > 1 else "Unknown"
        number = str(row[2]) if len(row) > 2 else "Unknown"
        service = str(row[3]) if len(row) > 3 else "Unknown"
        message = str(row[4]) if len(row) > 4 else ""
        
        if not number or number.startswith("0,0,0") or not message:
            return False
            
        if not is_recent_sms(ts, max_minutes_ago=10):
            return False
            
    except Exception as e:
        log.warning("Failed to parse SMS: %s", e)
        return False

    # Create unique message ID
    message_id = sha1(f"{ts}|{number}|{message}".encode()).hexdigest()
    
    if message_id in seen_messages:
        return False
        
    # Extract OTP code
    otp_code = extract_otp(message)
    
    # Get country and service icons
    country = get_country_from_operator(operator)
    service_icon = get_service_icon(service)
    
    # Format Telegram message
    telegram_msg = (
        f"🛡️ **{BOT_NAME}**\n"
        f"*{BOT_TAGLINE}*\n\n"
        f"✅ **Verification Code Detected**\n\n"
        f"🕰 **Time:** `{ts}`\n"
        f"📞 **Number:** `{number}`\n"
        f"🔢 **OTP Code:** `{otp_code}`\n"
        f"{country}\n"
        f"{service_icon}\n\n"
        f"💬 **Message:**\n`{message}`\n\n"
        f"_{BOT_USERNAME}_"
    )
    
    if send_telegram(telegram_msg):
        seen_messages.add(message_id)
        log.info("📤 Delivered OTP from %s: %s", number, otp_code)
        return True
    else:
        log.error("❌ Failed to send for %s", number)
        return False

# --- Health check ---
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
    if not BOT_TOKEN or not CHAT_IDS:
        log.error("❌ Missing BOT_TOKEN or CHAT_IDS")
        return
        
    if not MANUAL_SESSION:
        log.warning("⚠️ No MANUAL_SESSION, attempting auto-login")
        if not numberpanel_login():
            log.error("❌ No session available")
            return

    log.info("🚀 Starting %s", BOT_NAME)
    log.info("📞 %s", BOT_TAGLINE)
    log.info("🌐 Monitoring: %s", BASE_URL)
    log.info("⏰ Live OTPs only (10-minute window)")
    
    if not check_session_health():
        log.warning("⚠️ Session health check warning")
    
    consecutive_failures = 0
    max_consecutive_failures = 5
    
    while True:
        try:
            result = fetch_sms(minutes_back=10)
            
            if result in ["SESSION_EXPIRED", "NETWORK_ERROR", "ERROR"]:
                consecutive_failures += 1
                log.error("❌ Operation failed: %s (%d/%d)", 
                         result, consecutive_failures, max_consecutive_failures)
                
                if consecutive_failures >= max_consecutive_failures:
                    if result == "SESSION_EXPIRED":
                        log.error("🔐 Session expired")
                        # Try to re-login if credentials are available
                        if os.getenv("NUMBERPANEL_USERNAME"):
                            log.info("🔄 Attempting auto-relogin...")
                            if numberpanel_login():
                                consecutive_failures = 0
                                continue
                    log.error("💤 Waiting 5 minutes...")
                    time.sleep(300)
                    consecutive_failures = 0
                else:
                    time.sleep(60)
                continue
                
            consecutive_failures = 0
            
            if result and isinstance(result, list):
                processed_count = 0
                for sms_row in result:
                    if process_sms(sms_row):
                        processed_count += 1
                
                if processed_count > 0:
                    log.info("📨 Delivered %d OTPs", processed_count)
                else:
                    log.info("⏳ No new OTPs")
            else:
                log.info("⏳ No messages")
            
            time.sleep(POLL_INTERVAL)
                
        except KeyboardInterrupt:
            log.info("⏹️ %s stopped", BOT_NAME)
            break
        except Exception as e:
            log.exception("💥 Error: %s", e)
            time.sleep(30)

if __name__ == "__main__":
    main_loop()
