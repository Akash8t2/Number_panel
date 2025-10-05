#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IMS SMS Forwarder - DEBUG VERSION
Enhanced logging to diagnose authentication issues
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

# --- config via env ---
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

# --- enhanced logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(name)s - %(message)s"
)
log = logging.getLogger("imssms-debug")

# --- session with better headers ---
session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "Accept-Language": "en-US,en;q=0.5",
    "Accept-Encoding": "gzip, deflate, br",
    "DNT": "1",
    "Connection": "keep-alive",
    "Upgrade-Insecure-Requests": "1",
    "Sec-Fetch-Dest": "document",
    "Sec-Fetch-Mode": "navigate",
    "Sec-Fetch-Site": "same-origin",
})

# regex
OTP_RE = re.compile(r"\b\d{3,8}\b")
MATH_Q_RE = re.compile(r'What is\s*([0-9]+)\s*([+\-xX*\/])\s*([0-9]+)', re.I)

# --- seen local store ---
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

# --- helper to solve math captcha ---
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

# --- DEBUG: Save response to file for inspection ---
def save_debug_html(content, filename):
    try:
        with open(f"/tmp/{filename}", "w", encoding="utf-8") as f:
            f.write(content)
        log.info("💾 DEBUG: Saved %s", filename)
    except Exception as e:
        log.warning("Could not save debug file: %s", e)

# --- Enhanced login with detailed debugging ---
def ims_login(max_attempts=2):
    if not IMS_USERNAME or not IMS_PASSWORD:
        log.error("IMS_USERNAME / IMS_PASSWORD not set")
        return False

    attempt = 0
    while attempt < max_attempts:
        attempt += 1
        try:
            log.info("🔍 GET login page: %s", LOGIN_URL)
            r = session.get(LOGIN_URL, timeout=20)
            
            log.info("📄 Login page status: %d", r.status_code)
            log.info("🍪 Initial cookies: %s", session.cookies.get_dict())
            
            # Save login page for inspection
            save_debug_html(r.text, "login_page.html")
            
            if r.status_code == 403:
                log.error("❌ Login GET 403 Forbidden")
                log.error("Response headers: %s", dict(r.headers))
                return False
                
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")

            # Find form and extract all inputs
            form = soup.find("form")
            if not form:
                log.error("❌ No form found on login page")
                save_debug_html(r.text, "no_form_page.html")
                return False

            action = form.get("action", "")
            method = form.get("method", "post").lower()
            action_url = urljoin(LOGIN_URL, action)
            
            log.info("📝 Form action: %s (method: %s)", action_url, method)

            # Extract all form fields
            payload = {}
            username_field = None
            password_field = None
            
            for inp in form.find_all("input"):
                name = inp.get("name")
                value = inp.get("value", "")
                inp_type = (inp.get("type") or "text").lower()
                
                if not name:
                    continue
                    
                # Identify username/password fields
                lname = name.lower()
                if inp_type == "text" and any(x in lname for x in ["user", "email", "login"]):
                    username_field = name
                elif inp_type == "password":
                    password_field = name
                
                # Include hidden fields
                if inp_type == "hidden":
                    payload[name] = value
                    log.info("🔍 Hidden field: %s = %s", name, value[:50] + "..." if len(value) > 50 else value)

            # Fallback to common field names
            if not username_field:
                username_field = "username"
            if not password_field:
                password_field = "password"
                
            payload[username_field] = IMS_USERNAME
            payload[password_field] = IMS_PASSWORD

            log.info("👤 Username field: %s", username_field)
            log.info("🔒 Password field: %s", password_field)

            # Check for math captcha
            math_answer = solve_math(soup.get_text())
            if math_answer:
                log.info("🧮 Math captcha detected: answer = %s", math_answer)
                # Try common captcha field names
                for field in ["captcha", "answer", "verification", "math"]:
                    if field not in payload:
                        payload[field] = math_answer
                        log.info("📝 Added math answer to field: %s", field)
                        break

            log.info("📦 Final payload keys: %s", list(payload.keys()))

            # Prepare POST request
            headers = {
                "Referer": LOGIN_URL,
                "Origin": BASE_URL,
                "Content-Type": "application/x-www-form-urlencoded",
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
                "X-Requested-With": "XMLHttpRequest",
            }

            log.info("🚀 POST login to: %s", action_url)
            if method == "get":
                post_resp = session.get(action_url, params=payload, headers=headers, allow_redirects=True, timeout=20)
            else:
                post_resp = session.post(action_url, data=payload, headers=headers, allow_redirects=True, timeout=20)

            log.info("📨 Login POST status: %d", post_resp.status_code)
            log.info("🔐 Cookies after login: %s", session.cookies.get_dict())
            
            # Save login response for inspection
            save_debug_html(post_resp.text, "login_response.html")

            # Test dashboard access
            dashboard_url = urljoin(BASE_URL, "/client/SMSDashboard")
            log.info("🔍 Testing dashboard access: %s", dashboard_url)
            dash_resp = session.get(dashboard_url, timeout=15)
            
            log.info("📊 Dashboard status: %d", dash_resp.status_code)
            save_debug_html(dash_resp.text, "dashboard.html")

            # Check for success indicators
            success_indicators = [
                "SMSDashboard" in dash_resp.text,
                "logout" in dash_resp.text.lower(),
                "dashboard" in dash_resp.text.lower(),
                session.cookies.get_dict()  # Has cookies
            ]
            
            if any(success_indicators):
                log.info("✅ Login successful!")
                return True
            else:
                log.warning("⚠️ Login may have failed - no clear success indicators")
                if "login" in dash_resp.text.lower():
                    log.error("❌ Still seeing login page - credentials may be wrong")
                
        except Exception as e:
            log.exception("💥 Login attempt %d failed: %s", attempt, e)
            time.sleep(5)
            
    log.error("❌ All login attempts failed")
    return False

# --- Enhanced fetch with detailed debugging ---
def fetch_sms(minutes_back=15):
    try:
        now = datetime.now(timezone.utc)
        f1 = (now - timedelta(minutes=minutes_back)).strftime("%Y-%m-%d %H:%M:%S")
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
            "Referer": urljoin(BASE_URL, "/client/SMSDashboard"),
            "X-Requested-With": "XMLHttpRequest",
            "Accept": "application/json, text/javascript, */*; q=0.01",
        }
        
        log.info("🔍 Fetching SMS data from: %s", DATA_URL)
        log.info("📋 Fetch params: %s", {k: v for k, v in params.items() if not k.startswith('_')})
        log.info("🔐 Current cookies: %s", session.cookies.get_dict())
        
        r = session.get(DATA_URL, params=params, headers=headers, timeout=20)
        
        log.info("📡 Fetch status: %d", r.status_code)
        log.info("📄 Content-Type: %s", r.headers.get("Content-Type"))
        
        # Save the response for inspection
        save_debug_html(r.text, "api_response.html")
        
        if r.status_code != 200:
            log.warning("❌ Fetch failed with status: %d", r.status_code)
            if r.status_code in [401, 403]:
                log.error("🔐 Authentication issue - session may have expired")
            return []
            
        # Check if response is JSON
        content = r.text.strip()
        if content.startswith('{') or content.startswith('['):
            try:
                data = r.json()
                log.info("✅ Got JSON response with keys: %s", list(data.keys()) if isinstance(data, dict) else "array")
                return data.get("aaData", []) if isinstance(data, dict) else data
            except json.JSONDecodeError:
                log.error("❌ Failed to parse JSON")
                log.debug("Response start: %s", content[:500])
                return []
        else:
            log.warning("❌ Response is HTML, not JSON")
            if "login" in content.lower():
                log.error("🔐 Got login page - session expired")
            elif "cloudflare" in content.lower():
                log.error("🛡️ Cloudflare protection detected")
            return []
            
    except Exception as e:
        log.exception("💥 Fetch exception: %s", e)
        return []

# --- dedupe and forward (unchanged) ---
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
    mark_seen_id(mid, {"ts": ts, "num": number, "otp": otp})
    log.info("📤 Forwarded %s (%s)", number, otp)

# --- main loop ---
def main_loop():
    if not BOT_TOKEN or not CHAT_IDS:
        log.error("❌ Missing BOT_TOKEN or CHAT_IDS")
        return
    if not IMS_USERNAME or not IMS_PASSWORD:
        log.error("❌ Missing IMS_USERNAME / IMS_PASSWORD")
        return

    login_attempts = 0
    max_login_attempts = 3
    
    while True:
        try:
            if login_attempts >= max_login_attempts:
                log.error("🔴 Too many login failures, waiting 5 minutes")
                time.sleep(300)
                login_attempts = 0
                
            if not ims_login():
                login_attempts += 1
                log.error("🔴 Login failed (%d/%d) - waiting 60s", login_attempts, max_login_attempts)
                time.sleep(60)
                continue
                
            login_attempts = 0
            log.info("🚀 Starting SMS polling (interval: %ds)", POLL_INTERVAL)
            
            while True:
                rows = fetch_sms(minutes_back=15)
                log.info("📨 Fetched %d SMS records", len(rows))
                
                if rows:
                    for i, row in enumerate(rows):
                        if isinstance(row, list):
                            format_and_forward(row)
                        else:
                            log.warning("Unexpected row format: %s", type(row))
                
                time.sleep(POLL_INTERVAL)
                
        except KeyboardInterrupt:
            log.info("⏹️ Interrupted by user")
            break
        except Exception:
            log.exception("💥 Main loop error - restarting in 30s")
            time.sleep(30)

if __name__ == "__main__":
    main_loop()
