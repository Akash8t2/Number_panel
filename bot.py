#!/usr/bin/env python3
# bot.py -- Robust OTP forwarder for 45.82.67.20 -> Telegram
# Usage: set env vars then run
# Required ENV:
#   BOT_TOKEN       -> Telegram bot token
#   CHAT_IDS        -> comma-separated chat ids (where OTPs will be sent)
#   USERNAME        -> site username
#   PASSWORD        -> site password
# Optional ENV:
#   ADMIN_CHAT_IDS  -> comma-separated admin chat ids for alerts (optional)
#   SITE_BASE (default http://45.82.67.20)
#   POLL_INTERVAL (default 6 seconds)
#   KEEPALIVE_INTERVAL (default 300 seconds)
#   STATE_FILE (default processed_sms_ids.json)
#   REQUEST_TIMEOUT (default 15)
#   LOGIN_MIN_INTERVAL (default 5)
#   MAX_RELOGIN_TRIES (default 6)
# Requirements:
#   pip install requests beautifulsoup4 phonenumbers pycountry

import os
import time
import json
import logging
import random
import string
import re
from datetime import datetime, timedelta
from hashlib import sha1
from typing import Optional

import requests
from bs4 import BeautifulSoup
import phonenumbers
import pycountry

# ---------------- CONFIG ----------------
BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_IDS = os.getenv("CHAT_IDS", "")
ADMIN_CHAT_IDS = os.getenv("ADMIN_CHAT_IDS", "")  # optional alerts
USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")

SITE_BASE = os.getenv("SITE_BASE", "http://45.82.67.20")
LOGIN_PATH = os.getenv("LOGIN_PATH", "/ints/login")
SIGNIN_PATH = os.getenv("SIGNIN_PATH", "/ints/signin")
DASH_PATH = os.getenv("DASH_PATH", "/ints/agent/SMSDashboard")
DATA_API_PATH = os.getenv("DATA_API_PATH", "/ints/agent/res/data_smscdr.php")

POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "6"))
KEEPALIVE_INTERVAL = int(os.getenv("KEEPALIVE_INTERVAL", "300"))
STATE_FILE = os.getenv("STATE_FILE", "processed_sms_ids.json")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "15"))
LOGIN_MIN_INTERVAL = int(os.getenv("LOGIN_MIN_INTERVAL", "5"))
MAX_RELOGIN_TRIES = int(os.getenv("MAX_RELOGIN_TRIES", "6"))

USER_AGENT = os.getenv("USER_AGENT", "Mozilla/5.0 (X11; Linux x86_64)")

# ---------------- derived ----------------
if SITE_BASE.endswith("/"):
    SITE_BASE = SITE_BASE[:-1]
LOGIN_URL = SITE_BASE + LOGIN_PATH
SIGNIN_URL = SITE_BASE + SIGNIN_PATH
DASH_URL = SITE_BASE + DASH_PATH
DATA_API_URL = SITE_BASE + DATA_API_PATH

CHAT_IDS_LIST = [c.strip() for c in CHAT_IDS.split(",") if c.strip()]
ADMIN_CHAT_IDS_LIST = [c.strip() for c in ADMIN_CHAT_IDS.split(",") if c.strip()]
TELEGRAM_API_SEND = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

# ---------------- logging ----------------
logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s", level=logging.INFO)
logger = logging.getLogger("otp_forwarder")

# ---------------- state ----------------
def load_seen() -> set:
    if not os.path.exists(STATE_FILE):
        return set()
    try:
        with open(STATE_FILE, "r") as f:
            arr = json.load(f)
            return set(arr)
    except Exception:
        return set()

def save_seen(s: set):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(list(s), f)
    except Exception as e:
        logger.warning("Failed to save state file: %s", e)

seen = load_seen()

# ---------------- helpers ----------------
OTP_HYPH = re.compile(r'(\d{3}-\d{3})')
OTP_PLAIN = re.compile(r'\b(\d{3,8})\b')
DIGITS = re.compile(r'\d+')

def random_tail(n=10) -> str:
    return ''.join(random.choices("abcdefghijklmnopqrstuvwxyz0123456789", k=n))

def detect_service(text: str) -> str:
    if not text: return "Unknown"
    t = text.lower()
    if "whatsapp" in t: return "WhatsApp"
    if "telegram" in t: return "Telegram"
    if "gmail" in t or "google" in t: return "Gmail"
    if "facebook" in t: return "Facebook"
    return "Unknown"

def country_from_number(num: str) -> str:
    if not num: return "Unknown"
    candidates = [num]
    if not num.startswith("+"):
        candidates.insert(0, "+" + num)
    for n in candidates:
        try:
            parsed = phonenumbers.parse(n, None)
            region = phonenumbers.region_code_for_number(parsed)
            if region:
                country = pycountry.countries.get(alpha_2=region)
                if country:
                    return country.name
        except Exception:
            continue
    return "Unknown"

def format_for_telegram(entry: dict) -> str:
    number = entry.get("number", "N/A")
    code = entry.get("code", "N/A")
    service = entry.get("service", "Unknown")
    country = entry.get("country", "Unknown")
    ts = entry.get("time", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S"))
    msg = entry.get("message", "")
    code_plain = entry.get("code_plain", code)
    tail = random_tail(10)
    login_link = ""
    if ("telegram" in service.lower() or "telegram" in (msg or "").lower()) and code_plain not in (None, "N/A"):
        login_link = f"\nYou can also tap on this link to log in:\nhttps://t.me/login/{code_plain}\n"

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

def send_telegram(chat_id: str, text: str):
    try:
        r = requests.post(TELEGRAM_API_SEND, data={"chat_id": chat_id, "text": text}, timeout=10)
        if r.status_code != 200:
            logger.warning("Telegram send failed for %s: %s %s", chat_id, r.status_code, r.text[:200])
    except Exception as e:
        logger.exception("Telegram send error for %s: %s", chat_id, e)

def alert_admins(msg: str):
    for cid in ADMIN_CHAT_IDS_LIST:
        try:
            send_telegram(cid, f"[ALERT] {msg}")
        except Exception:
            pass

# ---------------- session & login ----------------
session: Optional[requests.Session] = None
_last_login_ts = 0
_last_keepalive = 0

def compute_math_answer_from_html(html: str) -> Optional[str]:
    # find arithmetic or first two numbers
    if not html:
        return None
    # try arithmetic
    m = re.search(r'(-?\d+)\s*([+\-xX*\/])\s*(-?\d+)', html)
    if m:
        a, op, b = int(m.group(1)), m.group(2), int(m.group(3))
        if op in ('+', '＋'): return str(a + b)
        if op in ('-', '−', '–'): return str(a - b)
        if op in ('x', 'X', '*', '×'): return str(a * b)
        if op == '/': return str(a // b if b != 0 else 0)
    nums = DIGITS.findall(html)
    if len(nums) >= 2:
        try:
            return str(int(nums[0]) + int(nums[1]))
        except Exception:
            return None
    return None

def login_session(force: bool = False) -> Optional[requests.Session]:
    """Create session and login. Throttled by LOGIN_MIN_INTERVAL."""
    global session, _last_login_ts
    now = time.time()
    if not force and now - _last_login_ts < LOGIN_MIN_INTERVAL and session:
        return session
    _last_login_ts = now

    if not USERNAME or not PASSWORD:
        logger.error("USERNAME/PASSWORD not set in env.")
        return None

    s = requests.Session()
    s.headers.update({
        "User-Agent": USER_AGENT,
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8"
    })

    try:
        r = s.get(LOGIN_URL, timeout=REQUEST_TIMEOUT)
    except Exception as e:
        logger.warning("GET login failed: %s", e)
        return None

    html = r.text or ""
    # compute captcha
    ans = compute_math_answer_from_html(html)
    if ans is None:
        # log snippet for debugging
        logger.warning("Could not find math captcha on login page. Snippet: %s", (html[:300].replace("\n"," ")))
        return None

    payload = {"username": USERNAME, "password": PASSWORD, "capt": ans}
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

    low = (post.text or "").lower()
    # heuristics for success
    if ("logout" in low) or ("/login" not in post.url.lower() and post.status_code in (200, 302, 303)):
        session = s
        logger.info("Login appears successful (post -> %s)", post.url)
        return session

    # try fetch dashboard to verify
    try:
        chk = s.get(DASH_URL, timeout=REQUEST_TIMEOUT)
        chk_text = (chk.text or "").lower()
        if chk.status_code < 400 and ("sms" in chk_text or "dashboard" in chk_text or "received" in chk_text):
            session = s
            logger.info("Login confirmed via dashboard fetch.")
            return session
    except Exception:
        pass

    # failed: log snippet
    snippet = (post.text or "")[:400].replace("\n", " ")
    logger.warning("Login not confirmed. Snippet: %s", snippet)
    return None

def ensure_session() -> Optional[requests.Session]:
    global session, _last_keepalive
    # if no session, login
    if session is None:
        return login_session()
    # keepalive to refresh cookie
    now = time.time()
    if now - _last_keepalive > KEEPALIVE_INTERVAL:
        try:
            r = session.get(DASH_URL, timeout=REQUEST_TIMEOUT)
            _last_keepalive = now
            body = (r.text or "").lower()
            if r.status_code >= 400 or ("username" in body and "password" in body) or ("what is" in body and "?" in body):
                logger.info("Keepalive indicates session expired. Re-login.")
                try:
                    session.close()
                except Exception:
                    pass
                session = login_session(force=True)
        except Exception as e:
            logger.info("Keepalive probe failed: %s. Re-login.", e)
            try:
                session.close()
            except Exception:
                pass
            session = login_session(force=True)
    return session

# ---------------- data API ----------------
def fetch_rows() -> Optional[list]:
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
    tried_relogin = False
    for attempt in range(2):
        try:
            if s:
                r = s.get(DATA_API_URL, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
            else:
                r = requests.get(DATA_API_URL, params=params, headers=headers, timeout=REQUEST_TIMEOUT)
        except Exception as e:
            logger.warning("Data API request attempt %d failed: %s", attempt+1, e)
            if s and not tried_relogin:
                tried_relogin = True
                s = login_session(force=True)
                continue
            return None

        body = r.text or ""
        lower = body.lower()

        # Detect HTML/login page
        if ("<html" in lower and "login" in lower) or ("username" in lower and "password" in lower) or ("what is" in lower and "?" in lower):
            snippet = (body[:300].replace("\n"," ") if body else "")
            logger.info("Data API returned login/html page snippet: %s", snippet[:200])
            # re-login once then retry
            if not tried_relogin:
                tried_relogin = True
                s = login_session(force=True)
                continue
            else:
                return None

        # Try parse JSON
        try:
            data = r.json()
            aa = data.get("aaData", [])
            return aa
        except Exception:
            # try to salvage JSON inside body
            start = body.find("{"); end = body.rfind("}") + 1
            if start != -1 and end != -1:
                try:
                    data = json.loads(body[start:end])
                    return data.get("aaData", [])
                except Exception:
                    logger.exception("Failed parsing JSON after trimming")
                    return None
            logger.warning("Data API returned non-JSON content but not login page.")
            return None
    return None

def parse_row(row: list) -> Optional[dict]:
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
    country = country_from_number(number)
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

# ---------------- main loop ----------------
def poll_once():
    aa = fetch_rows()
    if not aa:
        logger.debug("No rows returned this cycle.")
        return
    # process oldest-first
    for row in reversed(aa):
        entry = parse_row(row)
        if not entry:
            continue
        uid = entry.get("id")
        if not uid or uid in seen:
            continue
        seen.add(uid)
        text = format_for_telegram(entry)
        logger.info("Forwarding OTP id=%s number=%s code=%s", uid[:8], entry.get("number"), entry.get("code"))
        for cid in CHAT_IDS_LIST:
            send_telegram(cid, text)
            time.sleep(0.12)
    if aa:
        save_seen(seen)

def run():
    # basic validation
    if not BOT_TOKEN or not CHAT_IDS_LIST:
        logger.error("BOT_TOKEN and CHAT_IDS env vars are required. Exiting.")
        raise SystemExit(1)
    if not USERNAME or not PASSWORD:
        logger.error("USERNAME and PASSWORD env vars are required. Exiting.")
        raise SystemExit(1)

    # attempt initial login, with retries and admin alert on repeated failure
    relogin_tries = 0
    while True:
        s = login_session()
        if s:
            logger.info("Initial login successful.")
            break
        relogin_tries += 1
        logger.warning("Initial login attempt %d failed.", relogin_tries)
        if relogin_tries >= MAX_RELOGIN_TRIES:
            alert_admins(f"OTP forwarder failed to login after {relogin_tries} attempts. Check credentials / site.")
            logger.error("Giving up after %d failed login attempts.", relogin_tries)
            time.sleep(60)
            relogin_tries = 0
        time.sleep(min(10 * relogin_tries, 60))

    # main loop
    try:
        last_keepalive = time.time()
        while True:
            try:
                poll_once()
            except Exception:
                logger.exception("Unhandled error in poll cycle.")
            # keepalive: occasionally hit dashboard to refresh session
            if time.time() - last_keepalive > KEEPALIVE_INTERVAL:
                try:
                    s = ensure_session()
                    last_keepalive = time.time()
                except Exception:
                    logger.exception("Keepalive check failed.")
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        logger.info("Interrupted by user, saving state.")
        save_seen(seen)

if __name__ == "__main__":
    run()
