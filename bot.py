#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
otp_forwarder_complete.py
- Login: GET /ints/login -> solve simple math captcha -> POST /ints/signin
- Fetch JSON: /ints/agent/res/data_smscdr.php
- Parse aaData rows -> extract OTP -> send to Telegram chats
- Persistent dedupe (STATE_FILE)
"""

import os
import time
import json
import logging
import re
import random
import string
from datetime import datetime, timedelta
from hashlib import sha1
from typing import Optional

import requests
from bs4 import BeautifulSoup
import phonenumbers
import pycountry

# ---------------- CONFIG (env) ----------------
BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_IDS = os.getenv("CHAT_IDS", "")        # comma separated chat IDs
USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")

SITE_BASE = os.getenv("SITE_BASE", "http://45.82.67.20")
LOGIN_PATH = os.getenv("LOGIN_PATH", "/ints/login")
SIGNIN_PATH = os.getenv("SIGNIN_PATH", "/ints/signin")
DASH_PATH = os.getenv("DASH_PATH", "/ints/agent/SMSDashboard")
DATA_API_PATH = os.getenv("DATA_API_PATH", "/ints/agent/res/data_smscdr.php")

POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "6"))   # seconds
STATE_FILE = os.getenv("STATE_FILE", "processed_sms_ids.json")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "15"))
USER_AGENT = os.getenv("USER_AGENT", "Mozilla/5.0 (X11; Linux x86_64)")

# ---------------- derived ----------------
if SITE_BASE.endswith("/"):
    SITE_BASE = SITE_BASE[:-1]
LOGIN_URL = SITE_BASE + LOGIN_PATH
SIGNIN_URL = SITE_BASE + SIGNIN_PATH
DASH_URL = SITE_BASE + DASH_PATH
DATA_API_URL = SITE_BASE + DATA_API_PATH

CHAT_IDS_LIST = [c.strip() for c in CHAT_IDS.split(",") if c.strip()]
TELEGRAM_API_SEND = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

# ---------------- logging ----------------
logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s", level=logging.INFO)
logger = logging.getLogger("otp_forwarder_complete")

# ---------------- state helpers ----------------
def load_seen() -> set:
    if not os.path.exists(STATE_FILE):
        return set()
    try:
        with open(STATE_FILE, "r") as f:
            arr = json.load(f)
            return set(arr)
    except Exception:
        return set()

def save_seen(seen_set: set):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(list(seen_set), f)
    except Exception as e:
        logger.warning("Could not save state file: %s", e)

seen = load_seen()

# ---------------- regex/helpers ----------------
OTP_HYPH = re.compile(r'(\d{3}-\d{3})')
OTP_PLAIN = re.compile(r'\b(\d{3,8})\b')
DIGITS = re.compile(r'\d+')

def random_tail(n=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=n))

def detect_service(text: str) -> str:
    if not text: return "Unknown"
    t = text.lower()
    if "whatsapp" in t: return "WhatsApp"
    if "telegram" in t: return "Telegram"
    if "gmail" in t or "google" in t: return "Gmail"
    if "facebook" in t: return "Facebook"
    return "Unknown"

def get_country(number: str) -> str:
    if not number: return "Unknown"
    candidates = [number]
    if not number.startswith("+"):
        candidates.insert(0, "+" + number)
    for n in candidates:
        try:
            pn = phonenumbers.parse(n, None)
            region = phonenumbers.region_code_for_number(pn)
            if region:
                c = pycountry.countries.get(alpha_2=region)
                if c: return c.name
        except Exception:
            continue
    return "Unknown"

# ---------------- session & login ----------------
session: Optional[requests.Session] = None
_last_login = 0
LOGIN_MIN_INTERVAL = 5

def compute_math_from_text(text: str) -> Optional[str]:
    """Try to find a simple math pair and return their sum as string."""
    if not text:
        return None
    # look for expressions with operator
    m = re.search(r'(-?\d+)\s*([+\-xX*\/])\s*(-?\d+)', text)
    if m:
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        try:
            if op in ['+', '＋']: return str(a + b)
            if op in ['-', '−', '–']: return str(a - b)
            if op in ['x','X','*','×']: return str(a * b)
            if op == '/': return str(a // b if b != 0 else 0)
        except Exception:
            return None
    # fallback: first two digits found
    nums = DIGITS.findall(text)
    if len(nums) >= 2:
        try:
            return str(int(nums[0]) + int(nums[1]))
        except Exception:
            return None
    return None

def login_session() -> Optional[requests.Session]:
    """Create and return an authenticated session (or None)."""
    global session, _last_login
    now = time.time()
    if now - _last_login < LOGIN_MIN_INTERVAL:
        logger.debug("Login throttled.")
        return session
    _last_login = now

    if not USERNAME or not PASSWORD:
        logger.error("USERNAME or PASSWORD not set.")
        return None

    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Referer": SITE_BASE})

    try:
        r = s.get(LOGIN_URL, timeout=REQUEST_TIMEOUT)
    except Exception as e:
        logger.warning("GET login failed: %s", e)
        return None

    page_text = r.text or ""
    # compute captcha
    answer = compute_math_from_text(page_text)
    if answer is None:
        nums = DIGITS.findall(page_text)
        if len(nums) >= 2:
            try:
                answer = str(int(nums[0]) + int(nums[1]))
            except Exception:
                answer = None

    if answer is None:
        logger.warning("Could not find/solve math captcha on login page. Snippet: %s", (page_text[:200].replace("\n"," ")))
        return None

    payload = {
        "username": USERNAME,
        "password": PASSWORD,
        "capt": answer
    }
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

    lower = (post.text or "").lower()
    # heuristics for success
    if "logout" in lower or ("/login" not in post.url.lower() and post.status_code in (200, 302, 303)):
        session = s
        logger.info("Login appears successful.")
        return session
    # verify by fetching dashboard
    try:
        chk = s.get(DASH_URL, timeout=REQUEST_TIMEOUT)
        chk_text = (chk.text or "").lower()
        if chk.status_code < 400 and ("sms" in chk_text or "dashboard" in chk_text or "received" in chk_text):
            session = s
            logger.info("Login confirmed via dashboard.")
            return session
    except Exception:
        pass

    logger.warning("Login not confirmed. Snippet: %s", ((post.text or "")[:300].replace("\n"," ")))
    return None

def ensure_session() -> Optional[requests.Session]:
    """Return a usable session (login if needed)."""
    global session
    if session is None:
        session = login_session()
    else:
        # probe data API quickly to ensure not redirected
        try:
            r = session.get(DATA_API_URL, params={"_": int(time.time()*1000)}, timeout=REQUEST_TIMEOUT)
            body = (r.text or "").lower()
            if r.status_code >= 400 or ("username" in body and "password" in body) or ("what is" in body and "?" in body):
                logger.info("Session invalid according to probe; re-login.")
                try:
                    session.close()
                except Exception:
                    pass
                session = login_session()
        except Exception:
            logger.info("Session probe failed; re-login.")
            try:
                session.close()
            except Exception:
                pass
            session = login_session()
    return session

# ---------------- data fetch & parse ----------------
def fetch_json_rows() -> Optional[list]:
    """Return aaData list or None."""
    # params: last 24 hours by default
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
        "iDisplayLength": "100",
        "_": str(int(time.time() * 1000))
    }
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": DASH_URL
    }

    s = ensure_session()
    tried = False
    for attempt in range(2):
        try:
            if s:
                r = s.get(DATA_API_URL, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
            else:
                r = requests.get(DATA_API_URL, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        except Exception as e:
            logger.warning("Data API request attempt %d failed: %s", attempt+1, e)
            if s and not tried:
                tried = True
                s = login_session()
                continue
            return None

        body = r.text or ""
        lower = body.lower()
        # detect HTML login page
        if ("username" in lower and "password" in lower) or ("what is" in lower and "?" in lower) or ("<html" in lower and "login" in lower):
            snippet = (body[:300].replace("\n"," ") if body else "")
            logger.info("Data API returned login/html page snippet: %s", snippet)
            if not tried:
                tried = True
                s = login_session()
                continue
            return None

        try:
            data = r.json()
            aa = data.get("aaData", [])
            return aa
        except Exception:
            # fallback: try to extract braces region
            start = body.find("{"); end = body.rfind("}") + 1
            if start != -1 and end != -1:
                try:
                    data = json.loads(body[start:end])
                    return data.get("aaData", [])
                except Exception:
                    logger.exception("JSON parse failed after trim")
                    return None
            logger.warning("Data API returned non-JSON response.")
            return None
    return None

def parse_row_to_entry(row: list) -> Optional[dict]:
    """Map row -> dict with id, time, number, service, message, code, country."""
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
    # otp extraction
    m = OTP_HYPH.search(message)
    if m:
        code = m.group(1)
        code_plain = code.replace("-", "")
    else:
        m2 = OTP_PLAIN.search(message)
        code = m2.group(1) if m2 else "N/A"
        code_plain = code

    # service detection preference: service_field if meaningful else message
    service_guess = str(service_field).strip() if service_field and str(service_field).strip() not in ("", "0", "-") else detect_service(message)

    country = get_country(number)
    uid_src = f"{number}|{message}|{ts}"
    uid = sha1(uid_src.encode("utf-8")).hexdigest()

    return {
        "id": uid,
        "time": ts,
        "operator": operator,
        "number": number,
        "service": service_guess,
        "client": client,
        "message": message,
        "code": code,
        "code_plain": code_plain,
        "country": country
    }

# ---------------- format & send ----------------
def format_message(entry: dict) -> str:
    number = entry.get("number", "N/A")
    code = entry.get("code", "N/A")
    service = entry.get("service", "Unknown")
    country = entry.get("country", "Unknown")
    ts = entry.get("time", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
    msg = entry.get("message", "")
    tail = random_tail(10)

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
    )
    return text

def send_telegram_to_all(text: str):
    for cid in CHAT_IDS_LIST:
        try:
            resp = requests.post(TELEGRAM_API_SEND, data={"chat_id": cid, "text": text}, timeout=10)
            if resp.status_code != 200:
                logger.warning("Telegram send failed for %s: %s %s", cid, resp.status_code, resp.text[:200])
        except Exception as e:
            logger.exception("Error sending to Telegram for %s: %s", cid, e)

# ---------------- main loop ----------------
def poll_cycle():
    aa = fetch_json_rows()
    if not aa:
        logger.debug("No rows returned this cycle.")
        return
    # aa is list of rows; they are usually sorted newest-first
    # process oldest-first for meaningful order
    for row in reversed(aa):
        entry = parse_row_to_entry(row)
        if not entry:
            continue
        uid = entry.get("id")
        if not uid or uid in seen:
            continue
        seen.add(uid)
        text = format_message(entry)
        logger.info("Forwarding OTP id=%s number=%s code=%s", uid[:8], entry.get("number"), entry.get("code"))
        send_telegram_to_all(text)
        time.sleep(0.15)
    if aa:
        save_seen(seen)

def main():
    logger.info("Starting OTP forwarder (complete).")
    # validations
    if not BOT_TOKEN or not CHAT_IDS_LIST:
        logger.error("BOT_TOKEN and CHAT_IDS env vars required. Exiting.")
        raise SystemExit(1)
    if not USERNAME or not PASSWORD:
        logger.error("USERNAME and PASSWORD env vars required for login. Exiting.")
        raise SystemExit(1)

    # initial login
    ensure_session()

    try:
        while True:
            try:
                poll_cycle()
            except Exception:
                logger.exception("Unhandled exception in poll cycle.")
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        logger.info("Interrupted by user; saving state.")
        save_seen(seen)

if __name__ == "__main__":
    main()
