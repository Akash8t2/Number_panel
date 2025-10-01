#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bot.py - Robust OTP forwarder for http://45.82.67.20
Key:
 - Correct login endpoint: http://45.82.67.20/ints/login
 - Uses requests.Session() so cookies (PHPSESSID) persist
 - Solves simple math captcha present in login page text
 - Auto re-login if data API returns HTML (login page)
 - Exponential backoff for repeated login failures
 - Sends OTPs to Telegram chats (multiple)
 - Optional admin alerts (ADMIN_CHAT_IDS) with sanitized snippets
"""

import os
import time
import json
import logging
import re
import random
import string
from hashlib import sha1
from datetime import datetime, timedelta
from typing import Optional
from urllib.parse import urljoin

import requests
from bs4 import BeautifulSoup

# ---------------- CONFIG (env) ----------------
BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_IDS = os.getenv("CHAT_IDS", "")           # comma-separated
ADMIN_CHAT_IDS = os.getenv("ADMIN_CHAT_IDS", "")  # comma-separated (optional)
USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")

SITE_BASE = os.getenv("SITE_BASE", "http://45.82.67.20").rstrip("/")
LOGIN_PATH = os.getenv("LOGIN_PATH", "/ints/login")
SIGNIN_PATH = os.getenv("SIGNIN_PATH", "/ints/signin")
DASH_PATH = os.getenv("DASH_PATH", "/ints/agent/SMSDashboard")
DATA_API_PATH = os.getenv("DATA_API_PATH", "/ints/agent/res/data_smscdr.php")

POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "6"))
STATE_FILE = os.getenv("STATE_FILE", "processed_sms_ids.json")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "15"))
USER_AGENT = os.getenv("USER_AGENT", "Mozilla/5.0 (X11; Linux x86_64)")
MAX_RELOGIN_TRIES = int(os.getenv("MAX_RELOGIN_TRIES", "6"))
BACKOFF_BASE = float(os.getenv("BACKOFF_BASE", "2.0"))

# ---------------- derived ----------------
LOGIN_URL = urljoin(SITE_BASE + "/", LOGIN_PATH.lstrip("/"))       # http://45.82.67.20/ints/login
SIGNIN_URL = urljoin(SITE_BASE + "/", SIGNIN_PATH.lstrip("/"))     # http://45.82.67.20/ints/signin
DASH_URL = urljoin(SITE_BASE + "/", DASH_PATH.lstrip("/"))
DATA_API_URL = urljoin(SITE_BASE + "/", DATA_API_PATH.lstrip("/"))

CHAT_IDS_LIST = [c.strip() for c in CHAT_IDS.split(",") if c.strip()]
ADMIN_CHAT_IDS_LIST = [c.strip() for c in ADMIN_CHAT_IDS.split(",") if c.strip()]
TELEGRAM_SEND_URL = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

# ---------------- logging ----------------
logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s", level=logging.INFO)
logger = logging.getLogger("otp_forwarder")

# ---------------- state helpers ----------------
def load_seen() -> set:
    if not os.path.exists(STATE_FILE):
        return set()
    try:
        with open(STATE_FILE, "r") as f:
            return set(json.load(f))
    except Exception:
        return set()

def save_seen(seen_set: set):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(list(seen_set), f)
    except Exception as e:
        logger.warning("Could not save state file: %s", e)

seen = load_seen()

# ---------------- small utilities ----------------
DIGITS = re.compile(r'\d+')
OTP_HYPH = re.compile(r'(\d{3}-\d{3})')
OTP_PLAIN = re.compile(r'\b(\d{3,8})\b')

def random_tail(n=10):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def sanitize_snippet(snippet: str) -> str:
    if not snippet:
        return ""
    s = snippet
    if USERNAME:
        s = s.replace(USERNAME, "[REDACTED_USERNAME]")
    if PASSWORD:
        s = s.replace(PASSWORD, "[REDACTED_PASSWORD]")
    s = re.sub(r'value=["\'].*?["\']', 'value="[REDACTED]"', s, flags=re.S|re.I)
    s = re.sub(r'(<script[\s\S]*?</script>)', '[SCRIPT_REMOVED]', s, flags=re.I)
    return (s[:900] + ("..." if len(s) > 900 else ""))

def detect_service(text: str) -> str:
    if not text: return "Unknown"
    t = text.lower()
    if "whatsapp" in t: return "WhatsApp"
    if "telegram" in t: return "Telegram"
    if "gmail" in t or "google" in t: return "Gmail"
    if "facebook" in t: return "Facebook"
    return "Unknown"

# ---------------- session & login ----------------
session: Optional[requests.Session] = None
_last_login_time = 0
LOGIN_MIN_INTERVAL = 3  # seconds to avoid aggressive re-login

def solve_math_from_text(text: str) -> Optional[str]:
    if not text:
        return None
    # find expressions like "6 + 5"
    m = re.search(r'(-?\d+)\s*([+\-xX*\/])\s*(-?\d+)', text)
    if m:
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        try:
            if op in ['+', '＋']: return str(a + b)
            if op in ['-', '−', '–']: return str(a - b)
            if op in ['x', 'X', '*', '×']: return str(a * b)
            if op == '/': return str(a // b if b != 0 else 0)
        except Exception:
            return None
    nums = DIGITS.findall(text)
    if len(nums) >= 2:
        try:
            return str(int(nums[0]) + int(nums[1]))
        except Exception:
            return None
    return None

def create_session_and_login(force: bool = False) -> Optional[requests.Session]:
    """
    Create a new session and perform login.
    Returns the logged-in session or None.
    """
    global session, _last_login_time
    now = time.time()
    if not force and session and now - _last_login_time < LOGIN_MIN_INTERVAL:
        return session
    _last_login_time = now

    if not USERNAME or not PASSWORD:
        logger.error("USERNAME or PASSWORD not set in environment variables.")
        return None

    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Referer": SITE_BASE})

    try:
        r = s.get(LOGIN_URL, timeout=REQUEST_TIMEOUT)
    except Exception as e:
        logger.warning("GET login page failed: %s", e)
        return None

    page_text = r.text or ""
    # attempt to find CSRF token if exists (name _token or csrf)
    soup = BeautifulSoup(page_text, "html.parser")
    token_input = soup.find("input", {"name": "_token"}) or soup.find("input", {"name": "csrf_token"}) or soup.find("input", {"name": "csrf"})
    token_value = token_input.get("value") if token_input and token_input.get("value") else None

    # solve math captcha from page text
    answer = solve_math_from_text(page_text)
    payload = {"username": USERNAME, "password": PASSWORD}
    if answer is not None:
        payload["capt"] = answer
    if token_value:
        # name could be _token or other; use the name attribute
        payload[token_input.get("name")] = token_value

    headers = {
        "User-Agent": USER_AGENT,
        "Referer": LOGIN_URL,
        "Origin": SITE_BASE,
        "Content-Type": "application/x-www-form-urlencoded"
    }

    try:
        post = s.post(SIGNIN_URL, data=payload, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    except Exception as e:
        logger.warning("Login POST failed: %s", e)
        return None

    # quick heuristics to confirm login
    low = (post.text or "").lower()
    if ("logout" in low) or ("/login" not in post.url.lower() and post.status_code in (200,302,303)):
        session = s
        logger.info("Login appears successful (post -> %s). Cookies: %s", post.url, s.cookies.get_dict())
        return session

    # try fetch dashboard to confirm
    try:
        chk = s.get(DASH_URL, timeout=REQUEST_TIMEOUT)
        chk_low = (chk.text or "").lower()
        if chk.status_code < 400 and ("sms" in chk_low or "dashboard" in chk_low or "received" in chk_low):
            session = s
            logger.info("Login confirmed via dashboard fetch. Cookies: %s", s.cookies.get_dict())
            return session
    except Exception:
        pass

    # failed login: notify admins with sanitized snippet
    snippet = sanitize_snippet((post.text or "")[:1000])
    logger.warning("Login not confirmed. Snippet: %s", snippet)
    notify_admins(f"Login failed. Snippet:\n{snippet}")
    return None

# ---------------- Telegram helpers ----------------
def send_telegram(chat_id: str, text: str):
    try:
        requests.post(TELEGRAM_SEND_URL, data={"chat_id": chat_id, "text": text}, timeout=10)
    except Exception as e:
        logger.warning("Failed to send Telegram to %s: %s", chat_id, e)

def notify_admins(message: str):
    if not ADMIN_CHAT_IDS_LIST:
        logger.debug("No ADMIN_CHAT_IDS configured; skip notify.")
        return
    for aid in ADMIN_CHAT_IDS_LIST:
        try:
            send_telegram(aid, "[OTP-FORWARDER ALERT]\n" + message)
            time.sleep(0.2)
        except Exception:
            pass

# ---------------- Data fetching & parsing ----------------
def fetch_data_rows() -> Optional[list]:
    now = datetime.utcnow()
    fdate2 = now.strftime("%Y-%m-%d %H:%M:%S")
    fdate1 = (now - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    params = {
        "fdate1": fdate1,
        "fdate2": fdate2,
        "frange": "",
        "fclient": "",
        "fnum": "",
        "fcli": "",
        "fgdate": "",
        "fgmonth": "",
        "fgrange": "",
        "fgclient": "",
        "fgnumber": "",
        "fgcli": "",
        "fg": "0",
        "sEcho": "1",
        "iColumns": "9",
        "iDisplayStart": "0",
        "iDisplayLength": "50",
        "_": str(int(time.time() * 1000))
    }

    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": DASH_URL
    }

    global session
    if session is None:
        session = create_session_and_login(force=True)

    tried_relogin = False
    for attempt in range(2):
        try:
            if session:
                r = session.get(DATA_API_URL, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
            else:
                r = requests.get(DATA_API_URL, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        except Exception as e:
            logger.warning("Data API request failed (attempt %d): %s", attempt + 1, e)
            if session and not tried_relogin:
                tried_relogin = True
                session = create_session_and_login(force=True)
                continue
            return None

        body = r.text or ""
        lower = body.lower()

        # If HTML/login returned
        if ("<html" in lower and "login" in lower) or ("username" in lower and "password" in lower) or ("what is" in lower and "?" in lower):
            snippet = sanitize_snippet(body[:1000])
            logger.info("Data API returned login/html page snippet (sanitized): %s", snippet[:200])
            notify_admins("Data API returned HTML (likely session expired). Snippet:\n" + snippet)
            if not tried_relogin:
                tried_relogin = True
                session = create_session_and_login(force=True)
                continue
            return None

        # parse JSON
        try:
            data = r.json()
            aa = data.get("aaData", [])
            return aa
        except Exception:
            # attempt to salvage JSON substring
            start = body.find("{"); end = body.rfind("}") + 1
            if start != -1 and end != -1:
                try:
                    data = json.loads(body[start:end])
                    return data.get("aaData", [])
                except Exception:
                    logger.exception("Failed to parse JSON after trimming.")
                    return None
            logger.warning("Data API returned non-JSON content.")
            return None
    return None

def parse_row(row):
    try:
        ts = row[0] if len(row) > 0 else ""
        operator = row[1] if len(row) > 1 else ""
        number = str(row[2]) if len(row) > 2 else ""
        service_field = row[3] if len(row) > 3 else ""
        client = row[4] if len(row) > 4 else ""
        message = row[5] if len(row) > 5 else ""
    except Exception:
        return None

    number = number.strip()
    m = OTP_HYPH.search(message)
    if m:
        code = m.group(1); code_plain = code.replace("-", "")
    else:
        m2 = OTP_PLAIN.search(message)
        code = m2.group(1) if m2 else "N/A"
        code_plain = code

    service_guess = str(service_field).strip() if service_field and str(service_field).strip() not in ("", "0", "-") else detect_service(message)
    uid = sha1(f"{number}|{message}|{ts}".encode("utf-8")).hexdigest()
    return {
        "id": uid,
        "time": ts,
        "operator": operator,
        "number": number,
        "service": service_guess,
        "client": client,
        "message": message,
        "code": code,
        "code_plain": code_plain
    }

def format_message(entry: dict) -> str:
    number = entry.get("number","N/A")
    code = entry.get("code","N/A")
    service = entry.get("service","Unknown")
    country = entry.get("operator","Unknown")
    ts = entry.get("time", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
    msg = entry.get("message","")
    tail = random_tail(8)
    login_link = ""
    if ("telegram" in service.lower() or "telegram" in (msg or "").lower()) and entry.get("code_plain") not in (None, "N/A"):
        login_link = f"\nYou can also tap on this link to log in:\nhttps://t.me/login/{entry.get('code_plain')}\n"
    text = (
        "˹𝐕𝐢𝐛𝐞ꭙ 𝐅ʟ𝐨𝐰™ ˼:\n"
        "🔔 You have successfully received OTP\n\n"
        f"📞 Number: {number}\n"
        f"🔑 Code: {code}\n"
        f"🏆 Service: {service}\n"
        f"🌎 Country: {country}\n"
        f"⏳ Time: {ts}\n\n"
        "💬 Message:\n"
        f"{msg}\n"
        f"{login_link}"
        f"{tail}"
    )
    return text

def send_to_all_chats(text: str):
    for cid in CHAT_IDS_LIST:
        try:
            requests.post(TELEGRAM_SEND_URL, data={"chat_id": cid, "text": text}, timeout=10)
            time.sleep(0.12)
        except Exception as e:
            logger.warning("Failed to send to %s: %s", cid, e)

# ---------------- main loop ----------------
def main():
    if not BOT_TOKEN or not CHAT_IDS_LIST:
        logger.error("BOT_TOKEN and CHAT_IDS env vars are required.")
        raise SystemExit(1)
    if not USERNAME or not PASSWORD:
        logger.error("USERNAME and PASSWORD env vars are required.")
        raise SystemExit(1)

    # initial login with backoff
    attempts = 0
    while True:
        s = create_session_and_login(force=True)
        if s:
            logger.info("Initial login successful.")
            break
        attempts += 1
        delay = min((BACKOFF_BASE ** attempts), 60)
        logger.warning("Initial login failed (attempt %d). Retrying in %s seconds.", attempts, delay)
        time.sleep(delay)
        if attempts >= MAX_RELOGIN_TRIES:
            notify_admins(f"Initial login failed {attempts} times. Waiting before retry.")
            time.sleep(60)
            attempts = 0

    # poll loop
    try:
        while True:
            try:
                rows = fetch_data_rows()
                if rows:
                    # forward in chronological order (oldest first)
                    for r in reversed(rows):
                        entry = parse_row(r)
                        if not entry:
                            continue
                        uid = entry.get("id")
                        if not uid or uid in seen:
                            continue
                        seen.add(uid)
                        text = format_message(entry)
                        logger.info("Forwarding OTP id=%s number=%s code=%s", uid[:8], entry.get("number"), entry.get("code"))
                        send_to_all_chats(text)
                    save_seen(seen)
                else:
                    logger.debug("No rows fetched this cycle.")
            except Exception:
                logger.exception("Unhandled exception in poll cycle.")
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        logger.info("Interrupted: saving state and exiting.")
        save_seen(seen)
    except Exception:
        logger.exception("Fatal error in main loop; saving state.")
        save_seen(seen)

if __name__ == "__main__":
    main()
