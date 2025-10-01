#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
bot.py - Robust OTP forwarder for http://45.82.67.20 (IMS-like)
Features:
 - Login (solves simple math captcha and reads optional CSRF token)
 - Reuses requests.Session() (cookies preserved)
 - Calls JSON API /ints/agent/res/data_smscdr.php with proper headers
 - Auto re-login on HTML/login responses with exponential backoff
 - Sends sanitized HTML/login snippets to ADMIN_CHAT_IDS for debugging
 - Persists seen message IDs to STATE_FILE to avoid duplicates
 - Forwards nicely formatted messages to multiple Telegram CHAT_IDS
 - Resistant to crashes: errors are caught and retried
Environment variables (required):
 - BOT_TOKEN, CHAT_IDS (comma-separated), USERNAME, PASSWORD
Optional:
 - ADMIN_CHAT_IDS (comma-separated) to receive alerts
 - SITE_BASE, POLL_INTERVAL, STATE_FILE, REQUEST_TIMEOUT, USER_AGENT, MAX_RELOGIN_TRIES
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

import requests
from bs4 import BeautifulSoup

# ---------------- Configuration from env ----------------
BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_IDS = os.getenv("CHAT_IDS", "")            # comma-separated target chat ids
ADMIN_CHAT_IDS = os.getenv("ADMIN_CHAT_IDS", "") # comma-separated admin chat ids (optional)
USERNAME = os.getenv("USERNAME")
PASSWORD = os.getenv("PASSWORD")

SITE_BASE = os.getenv("SITE_BASE", "http://45.82.67.20").rstrip("/")
LOGIN_PATH = os.getenv("LOGIN_PATH", "/ints/login")
SIGNIN_PATH = os.getenv("SIGNIN_PATH", "/ints/signin")
DASH_PATH = os.getenv("DASH_PATH", "/ints/agent/SMSDashboard")
DATA_API_PATH = os.getenv("DATA_API_PATH", "/ints/agent/res/data_smscdr.php")

POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "6"))  # seconds
STATE_FILE = os.getenv("STATE_FILE", "processed_sms_ids.json")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "15"))
USER_AGENT = os.getenv("USER_AGENT", "Mozilla/5.0 (X11; Linux x86_64)")
MAX_RELOGIN_TRIES = int(os.getenv("MAX_RELOGIN_TRIES", "6"))
BACKOFF_BASE = float(os.getenv("BACKOFF_BASE", "2.0"))  # exponential backoff base

# ---------------- Derived constants ----------------
LOGIN_URL = SITE_BASE + LOGIN_PATH
SIGNIN_URL = SITE_BASE + SIGNIN_PATH
DASH_URL = SITE_BASE + DASH_PATH
DATA_API_URL = SITE_BASE + DATA_API_PATH

CHAT_IDS_LIST = [c.strip() for c in CHAT_IDS.split(",") if c.strip()]
ADMIN_CHAT_IDS_LIST = [c.strip() for c in ADMIN_CHAT_IDS.split(",") if c.strip()]
TELEGRAM_SEND_URL = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

# ---------------- Logging ----------------
logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s", level=logging.INFO)
logger = logging.getLogger("otp_forwarder")

# ---------------- State helpers ----------------
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

# ---------------- Utilities ----------------
DIGITS = re.compile(r'\d+')
OTP_HYPH = re.compile(r'(\d{3}-\d{3})')
OTP_PLAIN = re.compile(r'\b(\d{3,8})\b')

def random_tail(n=10):
    return ''.join(random.choices(string.ascii_lowercase + string.digits, k=n))

def sanitize_snippet(snippet: str) -> str:
    """Sanitize snippet before sending it to admins: mask password/username occurrences."""
    if not snippet:
        return ""
    s = snippet
    # mask obvious username/password values if present in env
    if USERNAME:
        s = s.replace(USERNAME, "[REDACTED_USERNAME]")
    if PASSWORD:
        s = s.replace(PASSWORD, "[REDACTED_PASSWORD]")
    # remove long attribute values in inputs for safety
    s = re.sub(r'value=["\'].*?["\']', 'value="[REDACTED]"', s, flags=re.S|re.I)
    # clip to first 800 chars for admin message
    return s[:800] + ("..." if len(s) > 800 else "")

def detect_service(text: str) -> str:
    if not text: return "Unknown"
    t = text.lower()
    if "whatsapp" in t: return "WhatsApp"
    if "telegram" in t: return "Telegram"
    if "gmail" in t or "google" in t: return "Gmail"
    if "facebook" in t: return "Facebook"
    return "Unknown"

# ---------------- Session + Login ----------------
session: Optional[requests.Session] = None
_last_login_time = 0
LOGIN_MIN_INTERVAL = 3  # seconds

def solve_math_from_text(text: str) -> Optional[str]:
    if not text:
        return None
    # try find expression like "What is 6 + 5 = ?"
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
    nums = DIGITS.findall(text)
    if len(nums) >= 2:
        try:
            return str(int(nums[0]) + int(nums[1]))
        except Exception:
            return None
    return None

def discover_form_fields(soup: BeautifulSoup):
    """
    Attempt to find canonical field names for username, password, captcha and CSRF token.
    Returns tuple (username_field_name, password_field_name, captcha_field_name, token_field_name, token_value, form_action)
    """
    form = None
    for f in soup.find_all("form"):
        if f.find("input", {"type":"password"}):
            form = f
            break
    if not form:
        form = soup.find("form")
    username_field = None
    password_field = None
    captcha_field = None
    token_field = None
    token_value = None
    action = form.get("action") if form else None
    if form:
        for inp in form.find_all("input"):
            name = inp.get("name") or ""
            typ = (inp.get("type") or "").lower()
            placeholder = (inp.get("placeholder") or "").lower()
            if not username_field and (typ in ("text","email") or "user" in name.lower() or "email" in name.lower() or "username" in placeholder):
                username_field = name
            if not password_field and (typ == "password" or "pass" in name.lower()):
                password_field = name
            if not captcha_field and ("capt" in name.lower() or "captcha" in name.lower() or "answer" in name.lower()):
                captcha_field = name
            if ("_token" in name.lower() or "csrf" in name.lower()):
                token_field = name
                if inp.get("value"):
                    token_value = inp.get("value")
    return username_field, password_field, captcha_field, token_field, token_value, action

def create_session_and_login(force: bool = False) -> Optional[requests.Session]:
    """
    Create a session and login. Returns session or None.
    Uses math captcha solver, discovers CSRF token if present.
    """
    global session, _last_login_time
    now = time.time()
    if not force and session and now - _last_login_time < LOGIN_MIN_INTERVAL:
        return session
    _last_login_time = now

    if not USERNAME or not PASSWORD:
        logger.error("USERNAME or PASSWORD env vars are not set.")
        return None

    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Referer": SITE_BASE})
    try:
        resp = s.get(LOGIN_URL, timeout=REQUEST_TIMEOUT)
    except Exception as e:
        logger.warning("GET login page failed: %s", e)
        return None

    soup = BeautifulSoup(resp.text or "", "html.parser")
    uname_field, pass_field, captcha_field, token_field, token_value, action = discover_form_fields(soup)

    payload = {}
    # username
    if uname_field:
        payload[uname_field] = USERNAME
    else:
        payload["username"] = USERNAME

    # password
    if pass_field:
        payload[pass_field] = PASSWORD
    else:
        payload["password"] = PASSWORD

    # token if found
    if token_field:
        if token_value:
            payload[token_field] = token_value
        else:
            meta = soup.find("meta", {"name": "csrf-token"})
            if meta and meta.get("content"):
                payload[token_field] = meta.get("content")

    # captcha/math
    captcha_answer = None
    if captcha_field:
        # try to find label or surrounding text
        found_text = ""
        inp = soup.find("input", {"name": captcha_field})
        if inp:
            # label for id?
            if inp.has_attr("id"):
                lab = soup.find("label", {"for": inp.get("id")})
                if lab:
                    found_text = lab.get_text(" ", strip=True)
            if not found_text:
                # fallback to some surrounding text
                prev = inp.find_previous(string=True)
                if prev:
                    found_text = prev.strip()
        if not found_text:
            found_text = soup.get_text(" ", strip=True)
        captcha_answer = solve_math_from_text(found_text)
        if captcha_answer:
            payload[captcha_field] = captcha_answer

    # fallback: page contains math but no explicit captcha field -> use 'capt'
    if not captcha_field:
        all_text = soup.get_text(" ", strip=True)
        ans = solve_math_from_text(all_text)
        if ans:
            payload["capt"] = ans

    post_url = SIGNIN_URL
    if action:
        if action.startswith("http"):
            post_url = action
        else:
            post_url = SITE_BASE + action

    headers = {"User-Agent": USER_AGENT, "Referer": LOGIN_URL, "Origin": SITE_BASE}
    try:
        res = s.post(post_url, data=payload, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    except Exception as e:
        logger.warning("Login POST failed: %s", e)
        return None

    text_low = (res.text or "").lower()
    # heuristics for success
    if ("logout" in text_low) or ("/login" not in res.url.lower() and res.status_code in (200,302,303)):
        session = s
        logger.info("Login appears successful (post -> %s)", res.url)
        return session

    # confirm via dashboard fetch
    try:
        chk = s.get(DASH_URL, timeout=REQUEST_TIMEOUT)
        chk_low = (chk.text or "").lower()
        if chk.status_code < 400 and ("sms" in chk_low or "dashboard" in chk_low or "received" in chk_low):
            session = s
            logger.info("Login confirmed via dashboard fetch.")
            return session
    except Exception:
        pass

    snippet = sanitize_snippet((res.text or "")[:1000])
    logger.warning("Login not confirmed. Snippet: %s", snippet)
    # notify admins with sanitized snippet
    notify_admins(f"Login attempt failed. Snippet:\n{snippet}")
    return None

# ---------------- Telegram helpers ----------------
def send_telegram(chat_id: str, text: str):
    try:
        requests.post(TELEGRAM_SEND_URL, data={"chat_id": chat_id, "text": text}, timeout=10)
    except Exception as e:
        logger.warning("Failed to send Telegram to %s: %s", chat_id, e)

def notify_admins(message: str):
    if not ADMIN_CHAT_IDS_LIST:
        logger.debug("Admin notify skipped (no ADMIN_CHAT_IDS).")
        return
    for aid in ADMIN_CHAT_IDS_LIST:
        try:
            send_telegram(aid, "[OTP-FORWARDER ALERT]\n" + message)
            time.sleep(0.2)
        except Exception:
            pass

# ---------------- Data fetch + parse ----------------
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

        # detect HTML/login page -> re-login once
        if ("<html" in lower and "login" in lower) or ("username" in lower and "password" in lower) or ("what is" in lower and "?" in lower):
            snippet = sanitize_snippet(body[:1000])
            logger.info("Data API returned login/html page snippet: %s", snippet[:200])
            notify_admins("Data API returned HTML (likely session expired). Snippet:\n" + snippet)
            if not tried_relogin:
                tried_relogin = True
                session = create_session_and_login(force=True)
                continue
            else:
                return None

        # parse JSON
        try:
            data = r.json()
            aa = data.get("aaData", [])
            return aa
        except Exception:
            # try salvage JSON chunk
            start = body.find("{"); end = body.rfind("}") + 1
            if start != -1 and end != -1:
                try:
                    data = json.loads(body[start:end])
                    return data.get("aaData", [])
                except Exception:
                    logger.exception("JSON salvage parse failed")
                    return None
            logger.warning("Data API returned non-JSON and not HTML.")
            return None
    return None

def parse_row_to_entry(row):
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
    number = entry.get("number", "N/A")
    code = entry.get("code", "N/A")
    service = entry.get("service", "Unknown")
    country = entry.get("operator", "Unknown")
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

def send_to_all_chats(text: str):
    for cid in CHAT_IDS_LIST:
        try:
            requests.post(TELEGRAM_SEND_URL, data={"chat_id": cid, "text": text}, timeout=10)
            time.sleep(0.12)
        except Exception as e:
            logger.warning("Failed to send to %s: %s", cid, e)

# ---------------- Main polling loop ----------------
def main():
    # validations
    if not BOT_TOKEN or not CHAT_IDS_LIST:
        logger.error("BOT_TOKEN and CHAT_IDS environment variables are required.")
        raise SystemExit(1)
    if not USERNAME or not PASSWORD:
        logger.error("USERNAME and PASSWORD environment variables are required.")
        raise SystemExit(1)

    # initial login with retries & backoff
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
            notify_admins(f"Initial login failed {attempts} times. Waiting longer before retries.")
            time.sleep(60)
            attempts = 0

    # poll loop
    try:
        while True:
            try:
                rows = fetch_data_rows()
                if rows:
                    # process oldest-first
                    for r in reversed(rows):
                        entry = parse_row_to_entry(r)
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
                    logger.debug("No rows fetched this cycle or fetch failed.")
            except Exception:
                logger.exception("Unhandled exception in poll cycle.")
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        logger.info("Interrupted, saving state and exiting.")
        save_seen(seen)
    except Exception:
        logger.exception("Fatal error in main loop, saving state.")
        save_seen(seen)

if __name__ == "__main__":
    main()
