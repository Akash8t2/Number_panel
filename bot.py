#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IMS SMS Forwarder - WORKING VERSION
Based on successful API call parameters
"""

import os
import time
import json
import tempfile
import logging
import re
from hashlib import sha1
from datetime import datetime, timezone, timedelta
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

# --- config ---
BASE_URL = os.getenv("BASE_URL", "https://imssms.org").rstrip("/")
LOGIN_PATH = os.getenv("LOGIN_PATH", "/login")
DATA_API_PATH = os.getenv("IMSSMS_DATA_API_PATH", "/client/res/data_smscdr.php")
LOGIN_URL = urljoin(BASE_URL, LOGIN_PATH)
DATA_URL = urljoin(BASE_URL, DATA_API_PATH)

BOT_TOKEN = os.getenv("IMSSMS_BOT_TOKEN") or os.getenv("BOT_TOKEN")
CHAT_IDS_RAW = os.getenv("IMSSMS_CHAT_IDS") or os.getenv("CHAT_ID") or os.getenv("CHAT_IDS", "")
CHAT_IDS = [c.strip() for c in CHAT_IDS_RAW.split(",") if c.strip()]

IMS_USERNAME = os.getenv("IMS_USERNAME") or os.getenv("IMS_USER") or os.getenv("IMS_LOGIN")
IMS_PASSWORD = os.getenv("IMS_PASSWORD") or os.getenv("IMS_PASS")

POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "15"))
STATE_FILE = os.getenv("STATE_FILE", "seen_imssms.json")

# --- logging ---
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")
log = logging.getLogger("imssms-working")

# --- session ---
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
})

# regex
OTP_RE = re.compile(r"\b\d{3,8}\b")
MATH_Q_RE = re.compile(r'What is\s*([0-9]+)\s*([+\-xX*\/])\s*([0-9]+)', re.I)

# --- seen storage ---
def load_seen():
    try:
        if os.path.exists(STATE_FILE):
            with open(STATE_FILE, "r") as f:
                return set(json.load(f))
    except Exception:
        log.exception("Failed to load seen file")
    return set()

def save_seen(seen_set):
    try:
        fd, tmp = tempfile.mkstemp()
        with os.fdopen(fd, "w") as f:
            json.dump(list(seen_set), f)
        os.replace(tmp, STATE_FILE)
    except Exception:
        log.exception("Failed to save seen file")

seen = load_seen()

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
        except Exception as e:
            log.warning("Telegram send exception: %s", e)

# --- Math solver ---
def solve_math(text):
    m = MATH_Q_RE.search(text or "")
    if not m:
        return None
    a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
    if op == "+":
        return str(a + b)
    if op == "-":
        return str(a - b)
    if op in ("x", "X", "*"):
        return str(a * b)
    if op == "/":
        return str(a // b if b != 0 else 0)
    return None

# --- Login function ---
def ims_login(max_attempts=3):
    if not IMS_USERNAME or not IMS_PASSWORD:
        log.error("IMS_USERNAME / IMS_PASSWORD not set")
        return False

    for attempt in range(1, max_attempts + 1):
        try:
            log.info("GET login page: %s", LOGIN_URL)
            r = session.get(LOGIN_URL, timeout=15)
            
            if r.status_code != 200:
                log.error("Login GET failed: %s", r.status_code)
                continue
                
            soup = BeautifulSoup(r.text, "html.parser")
            form = soup.find("form")
            if not form:
                log.error("No login form found")
                continue

            action = form.get("action", "")
            action_url = urljoin(LOGIN_URL, action)

            # Extract all form fields
            payload = {}
            for inp in form.find_all("input"):
                name = inp.get("name")
                value = inp.get("value", "")
                if name:
                    payload[name] = value

            # Set credentials
            payload["username"] = IMS_USERNAME
            payload["password"] = IMS_PASSWORD

            # Math captcha
            math_answer = solve_math(soup.get_text())
            if math_answer:
                payload["captcha"] = math_answer

            # Login headers
            headers = {
                "Referer": LOGIN_URL,
                "Origin": BASE_URL,
                "Content-Type": "application/x-www-form-urlencoded",
                "X-Requested-With": "XMLHttpRequest",
            }

            log.info("POST login to: %s", action_url)
            post = session.post(action_url, data=payload, headers=headers, allow_redirects=True, timeout=20)
            
            log.info("Login POST status: %s", post.status_code)
            log.info("Cookies after login: %s", session.cookies.get_dict())

            # Verify login by accessing dashboard
            dashboard_url = urljoin(BASE_URL, "/client/SMSDashboard")
            dash = session.get(dashboard_url, timeout=15)
            
            if dash.status_code == 200 and "SMSDashboard" in dash.text:
                log.info("✅ Login successful!")
                return True
            else:
                log.warning("Dashboard verification failed")
                continue

        except Exception as e:
            log.exception("Login attempt %d failed: %s", attempt, e)
            time.sleep(5)
            
    log.error("All login attempts failed")
    return False

# --- WORKING FETCH - Based on successful API call ---
def fetch_sms(minutes_back=15):
    try:
        now = datetime.now(timezone.utc)
        f1 = (now - timedelta(minutes=minutes_back)).strftime("%Y-%m-%d %H:%M:%S")
        f2 = now.strftime("%Y-%m-%d %H:%M:%S")
        
        # EXACT parameters from successful API call
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
        
        # EXACT headers from successful API call
        headers = {
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": f"{BASE_URL}/client/SMSDashboard",
            "Cache-Control": "no-store, no-cache, must-revalidate",
            "Pragma": "no-cache",
        }

        log.info("Fetching SMS data from: %s", DATA_URL)
        
        r = session.get(DATA_URL, params=params, headers=headers, timeout=20)
        
        log.info("Fetch status: %d", r.status_code)
        log.info("Content-Type: %s", r.headers.get("Content-Type"))
        
        if r.status_code != 200:
            log.warning("Fetch failed with status: %d", r.status_code)
            return []
            
        # Check response content
        content = r.text.strip()
        
        # Parse JSON response
        try:
            data = r.json()
            if isinstance(data, dict) and "aaData" in data:
                log.info("✅ SUCCESS! Got %d SMS records", len(data["aaData"]))
                return data["aaData"]
            else:
                log.info("Got JSON response: %s", list(data.keys()) if isinstance(data, dict) else type(data))
                return data if isinstance(data, list) else []
        except json.JSONDecodeError as e:
            log.error("JSON parse failed: %s", e)
            # Check if we got HTML instead
            if content.startswith('<!DOCTYPE html>') or content.startswith('<html'):
                log.error("Got HTML instead of JSON - session may have expired")
                if 'login' in content.lower():
                    log.error("Confirmed: Got login page")
                return "SESSION_EXPIRED"
            return []
            
    except Exception as e:
        log.exception("Fetch exception: %s", e)
        return []

# --- Forwarding ---
def already_seen_id(mid):
    return mid in seen

def mark_seen_id(mid, payload=None):
    seen.add(mid)
    save_seen(seen)

def format_and_forward(row):
    try:
        ts = row[0] if len(row) > 0 else ""
        operator = row[1] if len(row) > 1 else ""
        number = row[2] if len(row) > 2 else ""
        service = row[3] if len(row) > 3 else ""
        message = row[4] if len(row) > 4 else ""
    except Exception:
        log.warning("Malformed row: %s", row)
        return

    mid = sha1(f"{ts}|{number}|{message}".encode()).hexdigest()
    if already_seen_id(mid):
        return

    otps = OTP_RE.findall(message or "")
    otp = otps[-1] if otps else "N/A"
    text = (
        f"✅ *New OTP*\n"
        f"🌐 {BASE_URL}\n"
        f"🕰 {ts}\n"
        f"📞 {number}\n"
        f"🔢 OTP: `{otp}`\n"
        f"📡 {operator}\n"
        f"💬 {message}"
    )
    send_telegram(text)
    mark_seen_id(mid)
    log.info("📤 Forwarded %s (%s)", number, otp)

# --- Main loop ---
def main_loop():
    if not BOT_TOKEN or not CHAT_IDS:
        log.error("Missing BOT_TOKEN or CHAT_IDS")
        return
    if not IMS_USERNAME or not IMS_PASSWORD:
        log.error("Missing IMS_USERNAME / IMS_PASSWORD")
        return

    while True:
        try:
            if not ims_login():
                log.error("Login failed - waiting 60s")
                time.sleep(60)
                continue

            log.info("🚀 Starting SMS polling (interval: %ds)", POLL_INTERVAL)
            
            # Poll loop
            while True:
                result = fetch_sms(minutes_back=15)
                
                # Handle session expiration
                if result == "SESSION_EXPIRED":
                    log.warning("Session expired - reconnecting...")
                    break
                
                # Process SMS records
                if result and isinstance(result, list):
                    for row in result:
                        if isinstance(row, list):
                            format_and_forward(row)
                
                time.sleep(POLL_INTERVAL)
                
        except KeyboardInterrupt:
            log.info("Interrupted by user")
            break
        except Exception:
            log.exception("Main loop error - restarting in 30s")
            time.sleep(30)

if __name__ == "__main__":
    main_loop()
