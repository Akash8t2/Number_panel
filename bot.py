#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
otp_forwarder_login_json.py

- Logs into the dashboard (handles simple math captcha)
- Calls JSON endpoint /ints/agent/res/data_smscdr.php to fetch aaData rows
- Parses OTP, service, country, time, number and forwards to Telegram with
  iVasms-like formatting.
"""

import os
import time
import json
import logging
import requests
import re
import random
import string
from datetime import datetime, timedelta
from hashlib import sha1
from urllib.parse import urljoin, urlencode

from bs4 import BeautifulSoup
import phonenumbers
import pycountry

# ---------------- CONFIG (from env) ----------------
BOT_TOKEN = os.getenv("BOT_TOKEN")                # required
CHAT_IDS = os.getenv("CHAT_IDS", "")              # required, comma-separated
USERNAME = os.getenv("USERNAME")                  # required for login
PASSWORD = os.getenv("PASSWORD")                  # required for login

SITE_BASE = os.getenv("SITE_BASE", "http://45.82.67.20")
LOGIN_PATH = os.getenv("LOGIN_PATH", "/ints/")   # default root where login form lives
DASH_PATH = os.getenv("DASH_PATH", "/ints/agent/SMSDashboard")
CDR_PATH = os.getenv("CDR_PATH", "/ints/agent/SMSCDRStats")
DATA_API_PATH = os.getenv("DATA_API_PATH", "/ints/agent/res/data_smscdr.php")

POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "6"))  # seconds between polls
STATE_FILE = os.getenv("STATE_FILE", "processed_sms_ids.json")
MAX_SEEN = int(os.getenv("MAX_SEEN", "20000"))
USER_AGENT = os.getenv("USER_AGENT", "Mozilla/5.0 (X11; Linux x86_64)")
REQUEST_TIMEOUT = float(os.getenv("REQUEST_TIMEOUT", "15"))

# ---------------- derived ----------------
if SITE_BASE.endswith("/"):
    SITE_BASE = SITE_BASE[:-1]
LOGIN_URL = urljoin(SITE_BASE + "/", LOGIN_PATH.lstrip("/"))
DASH_URL = urljoin(SITE_BASE + "/", DASH_PATH.lstrip("/"))
CDR_URL = urljoin(SITE_BASE + "/", CDR_PATH.lstrip("/"))
DATA_API_URL = urljoin(SITE_BASE + "/", DATA_API_PATH.lstrip("/"))

CHAT_IDS_LIST = [c.strip() for c in CHAT_IDS.split(",") if c.strip()]
TELEGRAM_API_SEND = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

# ---------------- logging ----------------
logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s", level=logging.INFO)
logger = logging.getLogger("otp_forwarder_json")

# ---------------- state helpers ----------------
def load_seen():
    if not os.path.exists(STATE_FILE):
        return set()
    try:
        with open(STATE_FILE, "r") as f:
            arr = json.load(f)
            return set(arr)
    except Exception:
        return set()

def save_seen(seen_set):
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(list(seen_set), f)
    except Exception as e:
        logger.warning("Could not save state file: %s", e)

seen = load_seen()

# ---------------- regex / small helpers ----------------
PHONE_RE = re.compile(r'(\+?\d{6,15})')
# we will accept hyphenated or plain numeric codes, 3-8 digits
OTP_RE_HYPHEN = re.compile(r'(\d{3}-\d{3})')
OTP_RE_PLAIN = re.compile(r'\b(\d{3,8})\b')

def random_tail(length=10):
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# ---------------- service & country detection ----------------
SERVICE_MAP_KEYWORDS = {
    "Telegram": ["telegram"],
    "WhatsApp": ["whatsapp", "whats app"],
    "Facebook": ["facebook", "fb"],
    "Google": ["google", "gmail", "gsuite"],
    "Instagram": ["instagram"],
    "Gmail": ["gmail"],
    "Netflix": ["netflix"],
    "Amazon": ["amazon"],
    "PayPal": ["paypal"],
    "Twitter": ["twitter", "x "],
    "Steam": ["steam"]
}
SERVICE_EMOJIS = {
    "Telegram": "📩", "WhatsApp": "💚", "Facebook": "📘", "Google": "🔍", "Instagram": "📷",
    "Gmail": "✉️", "Netflix": "🎬", "Amazon": "🛒", "PayPal": "💰", "Twitter": "🐦", "Unknown": "❓"
}

def detect_service_from_text(text):
    if not text:
        return "Unknown"
    low = text.lower()
    for name, keys in SERVICE_MAP_KEYWORDS.items():
        for k in keys:
            if k in low:
                return name
    return "Unknown"

def get_country_from_number(number):
    if not number:
        return "Unknown"
    # ensure we try with leading + if not present
    test_nums = [number]
    if not number.startswith("+"):
        test_nums.insert(0, "+" + number)
    for num in test_nums:
        try:
            parsed = phonenumbers.parse(num, None)
            region = phonenumbers.region_code_for_number(parsed)
            if region:
                country = pycountry.countries.get(alpha_2=region)
                if country:
                    return country.name
        except Exception:
            continue
    return "Unknown"

# ---------------- login / session with math-captcha solver ----------------
session = None
_last_login_attempt = 0
LOGIN_MIN_INTERVAL = 5  # seconds between login attempts to avoid hammering

def compute_simple_math_answer(text):
    """Parse simple math in text like 'What is 1 + 0 = ?' or 'What is 4 + 8 = ?'"""
    if not text:
        return None
    # Common patterns: '1 + 0', '4 + 8 = ?', 'What is 1 + 0 = ?'
    m = re.search(r'(-?\d+)\s*([+\-xX*\/])\s*(-?\d+)', text)
    if m:
        a = int(m.group(1))
        op = m.group(2)
        b = int(m.group(3))
        try:
            if op in ['+', '＋']:
                return str(a + b)
            if op in ['-', '−', '–']:
                return str(a - b)
            if op in ['x', 'X', '*', '×']:
                return str(a * b)
            if op == '/':
                return str(a // b if b != 0 else 0)
        except Exception:
            return None
    m2 = re.search(r'(\d+)\s*\+\s*(\d+)', text)
    if m2:
        return str(int(m2.group(1)) + int(m2.group(2)))
    return None

def discover_form_fields(form):
    """
    Inspect a BeautifulSoup form and try to find username, password, captcha and token.
    Returns names: username_field, password_field, captcha_field, token_field_name, token_value, action_url
    """
    inputs = form.find_all("input")
    username_field = None
    password_field = None
    captcha_field = None
    token_field = None
    token_value = None

    for inp in inputs:
        name = inp.get("name")
        itype = (inp.get("type") or "").lower()
        placeholder = (inp.get("placeholder") or "").lower()
        if not username_field:
            if itype in ("text", "email") or (name and any(k in (name or "").lower() for k in ("user", "email", "username")) ) or ("username" in placeholder):
                username_field = name
        if not password_field:
            if itype == "password" or (name and "pass" in (name or "").lower()):
                password_field = name
        # token detection
        if name and ("_token" in name.lower() or "csrf" in name.lower() or name.lower().startswith("token")):
            token_field = name
            if inp.get("value"):
                token_value = inp.get("value")
        # captcha detection heuristics
        if not captcha_field and name:
            lname = (name or "").lower()
            if "captcha" in lname or "answer" in lname or "math" in lname or "security" in lname:
                captcha_field = name
        if not captcha_field and placeholder and ("?" in placeholder or "answer" in placeholder):
            captcha_field = name

    # fallback to first text input for username and first password for password if not found
    if not username_field:
        for inp in inputs:
            if (inp.get("type") or "").lower() in ("text", "email"):
                username_field = inp.get("name")
                break
    if not password_field:
        for inp in inputs:
            if (inp.get("type") or "").lower() == "password":
                password_field = inp.get("name")
                break

    action = form.get("action") or ""
    return username_field, password_field, captcha_field, token_field, token_value, action

def create_logged_session():
    """Attempt to login and return a requests.Session on success, else None"""
    global session, _last_login_attempt
    now = time.time()
    if now - _last_login_attempt < LOGIN_MIN_INTERVAL:
        return None
    _last_login_attempt = now

    if not USERNAME or not PASSWORD:
        logger.error("USERNAME/PASSWORD not set - cannot login.")
        return None

    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Referer": SITE_BASE})
    try:
        r = s.get(LOGIN_URL, timeout=REQUEST_TIMEOUT)
    except Exception as e:
        logger.warning("GET login page failed: %s", e)
        return None

    if r.status_code >= 400:
        # try root
        try:
            r = s.get(SITE_BASE, timeout=REQUEST_TIMEOUT)
        except Exception as e:
            logger.warning("GET site root failed: %s", e)
            return None

    soup = BeautifulSoup(r.text, "html.parser")
    login_form = None
    # find a form containing a password input
    for f in soup.find_all("form"):
        if f.find("input", {"type": "password"}):
            login_form = f
            break
    if not login_form:
        login_form = soup.find("form")

    if not login_form:
        logger.warning("No login form found on page.")
        return None

    username_field, password_field, captcha_field, token_field, token_value, action = discover_form_fields(login_form)
    post_url = urljoin(r.url, action) if action else r.url

    payload = {}
    if username_field:
        payload[username_field] = USERNAME
    else:
        payload['username'] = USERNAME
        payload['email'] = USERNAME
    if password_field:
        payload[password_field] = PASSWORD
    else:
        payload['password'] = PASSWORD

    if token_field:
        if token_value:
            payload[token_field] = token_value
        else:
            # try meta tag
            meta = soup.find("meta", {"name": "csrf-token"})
            if meta and meta.get("content"):
                payload[token_field] = meta.get("content")

    # if captcha field present, try to compute answer from surrounding text
    if captcha_field:
        # find label or text content near captcha input
        captcha_input = login_form.find("input", {"name": captcha_field})
        captcha_text = ""
        if captcha_input:
            # check label with for attr
            if captcha_input.has_attr("id"):
                label = login_form.find("label", {"for": captcha_input.get("id")})
                if label:
                    captcha_text = label.get_text(separator=" ", strip=True)
            if not captcha_text:
                # look at previous texts in form
                prev = captcha_input.find_previous(string=True)
                if prev:
                    captcha_text = prev.strip()
        if not captcha_text:
            captcha_text = login_form.get_text(separator=" ", strip=True)
        answer = compute_simple_math_answer(captcha_text)
        if answer is not None:
            payload[captcha_field] = answer
            logger.info("Solved captcha: '%s' -> %s", captcha_text, answer)
        else:
            logger.warning("Could not solve captcha automatically (text=%r).", captcha_text)

    headers = {"User-Agent": USER_AGENT, "Referer": r.url}
    try:
        post_res = s.post(post_url, data=payload, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    except Exception as e:
        logger.warning("Login POST failed: %s", e)
        return None

    body_low = (post_res.text or "").lower()
    if "logout" in body_low or "dashboard" in body_low or ("/login" not in str(post_res.url)):
        logger.info("Login appears successful (post -> %s)", post_res.url)
        session = s
        return session

    # try fetching dashboard to confirm
    try:
        chk = s.get(DASH_URL, timeout=REQUEST_TIMEOUT)
        if chk.status_code < 400 and ("sms" in (chk.text or "").lower() or "received" in (chk.text or "").lower()):
            logger.info("Login confirmed via dashboard fetch.")
            session = s
            return session
    except Exception:
        pass

    logger.warning("Login did not clearly succeed (status %s, url %s).", post_res.status_code, post_res.url)
    return None

def ensure_session():
    """Ensure session is valid; attempt login if not."""
    global session
    if session is None:
        session = create_logged_session()
    else:
        try:
            r = session.get(DASH_URL, timeout=REQUEST_TIMEOUT)
            body = (r.text or "").lower()
            if r.status_code >= 400 or ("login" in body and "password" in body):
                logger.info("Session expired or redirected to login; recreating session.")
                session = create_logged_session()
        except Exception:
            logger.info("Session probe failed; will recreate.")
            session = create_logged_session()
    return session

def clear_session():
    global session
    try:
        if session:
            session.close()
    except Exception:
        pass
    session = None

# ---------------- JSON API fetching & parsing ----------------
def call_data_api():
    """
    Call DATA_API_URL with parameters for last day (or current date) to fetch aaData JSON.
    Returns parsed JSON object or None.
    """
    # prepare params similar to what browser sends - keep display length reasonable
    today = datetime.utcnow()
    fdate2 = today.strftime("%Y-%m-%d %H:%M:%S")
    fdate1 = (today - timedelta(days=1)).strftime("%Y-%m-%d %H:%M:%S")
    # Base params minimal to get aaData, many can be left as default/empty
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
        "sColumns": ",,,,,,, ,",
        "iDisplayStart": "0",
        "iDisplayLength": "100",  # fetch up to 100 rows
        "_": str(int(time.time() * 1000))
    }
    # Join as query string
    query = DATA_API_URL + "?" + urlencode(params)
    s = ensure_session()
    headers = {
        "User-Agent": USER_AGENT,
        "Accept": "application/json, text/javascript, */*; q=0.01",
        "X-Requested-With": "XMLHttpRequest",
        "Referer": DASH_URL
    }
    # prefer session (authenticated) but allow fallback to plain GET
    if s:
        try:
            r = s.get(query, headers=headers, timeout=REQUEST_TIMEOUT)
            if r.status_code == 200:
                text = r.text
                # The server sometimes returns text/html but body is JSON
                try:
                    return json.loads(text)
                except Exception:
                    # strip any leading/trailing junk then parse
                    start = text.find("{")
                    end = text.rfind("}") + 1
                    if start != -1 and end != -1:
                        try:
                            return json.loads(text[start:end])
                        except Exception:
                            logger.exception("JSON parse failed after trimming")
                            return None
            else:
                logger.warning("Data API returned status %s", r.status_code)
        except Exception as e:
            logger.warning("Data API request via session failed: %s", e)
            clear_session()
            # fallback below to unauthenticated
    try:
        r = requests.get(query, headers=headers, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        try:
            return r.json()
        except Exception:
            text = r.text
            start = text.find("{")
            end = text.rfind("}") + 1
            if start != -1 and end != -1:
                try:
                    return json.loads(text[start:end])
                except Exception:
                    logger.exception("Fallback JSON parse failed")
                    return None
    except Exception as e:
        logger.warning("Data API unauthenticated GET failed: %s", e)
        return None

def parse_api_row(row):
    """
    Given a single row entry (list), map indices to fields and return dict:
    {id, time, number, message, service, code, country}
    Expected structure (based on sample): 
      [0]=time, [1]=operator, [2]=number, [3]=maybe cli/service, [4]=client, [5]=message, ...
    """
    try:
        time_str = row[0] if len(row) > 0 else ""
        number = str(row[2]) if len(row) > 2 else ""
        raw_service_field = str(row[3]) if len(row) > 3 else ""
        client = str(row[4]) if len(row) > 4 else ""
        message = str(row[5]) if len(row) > 5 else ""
    except Exception:
        return None

    # Normalize number: remove spaces
    number = number.strip()
    # Extract OTP: prefer hyphenated group (e.g., 934-045) then plain numeric
    code = None
    m = OTP_RE_HYPHEN.search(message)
    if m:
        code = m.group(1)
        # also remove hyphen for login link if needed
        code_plain = code.replace("-", "")
    else:
        m2 = OTP_RE_PLAIN.search(message)
        if m2:
            code = m2.group(1)
            code_plain = code
    if not code:
        code = "N/A"
        code_plain = "N/A"

    # Service detection: check raw_service_field then message text
    service_guess = "Unknown"
    if raw_service_field and raw_service_field.strip().lower() not in ("", "whatsapp", "sms", "whatsapp"):
        # sometimes 3rd or 4th column indicates "Whatsapp" or "Whatsapp" appears in sample as "Whatsapp"
        service_guess = raw_service_field.strip()
    else:
        service_guess = detect_service_from_text(message)

    country = get_country_from_number(number)

    uid_source = f"{number}|{message}|{time_str}"
    uid = sha1(uid_source.encode("utf-8")).hexdigest()

    return {
        "id": uid,
        "time": time_str,
        "number": number,
        "raw_service_field": raw_service_field,
        "client": client,
        "message": message,
        "service": service_guess,
        "code": code,
        "code_plain": code_plain,
        "country": country
    }

# ---------------- message formatting & sending ----------------
def format_for_telegram(entry):
    number = entry.get("number") or "N/A"
    code = entry.get("code") or "N/A"
    code_plain = entry.get("code_plain", code)
    text = entry.get("message", "")
    time_str = entry.get("time") or datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    service_name = entry.get("service") or "Unknown"
    service_emoji = SERVICE_EMOJIS.get(service_name, SERVICE_EMOJIS.get("Unknown"))
    country = entry.get("country") or "Unknown"
    tail = random_tail(10)

    login_link_section = ""
    # include t.me/login link if Telegram service or message mentions telegram
    if (("telegram" in (service_name or "").lower()) or ("telegram" in (text or "").lower())) and code_plain not in (None, "N/A"):
        login_link_section = f"\nYou can also tap on this link to log in:\nhttps://t.me/login/{code_plain}\n"

    # Build message — send as plain text (no Markdown) to avoid escaping issues
    msg = (
        "˹𝐕𝐢𝐛𝐞ꭙ 𝐅ʟ𝐨𝐰™ ˼:\n"
        "🔔 You have successfully received OTP\n\n"
        f"📞 Number: {number}\n"
        f"🔑 Code: {code}\n"
        f"🏆 Service: {service_emoji} {service_name}\n"
        f"🌎 Country: {country}\n"
        f"⏳ Time: {time_str}\n\n"
        "💬 Message:\n"
        f"{text}\n"
        f"{login_link_section}\n"
        f"{tail}"
    )
    return msg

def send_to_telegram(chat_id, text):
    payload = {"chat_id": chat_id, "text": text}
    try:
        r = requests.post(TELEGRAM_API_SEND, data=payload, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            logger.warning("Telegram send failed %s -> %s", r.status_code, r.text[:200])
    except Exception as e:
        logger.exception("Failed to send telegram message: %s", e)

# ---------------- main poll & forward logic ----------------
def poll_and_forward_once():
    global seen
    data = call_data_api()
    if not data:
        logger.debug("No data returned from API.")
        return
    aa = data.get("aaData") if isinstance(data, dict) else None
    if not aa:
        logger.debug("aaData not found or empty.")
        return
    new_count = 0
    # aaData is list of rows (each row is a list)
    for row in aa:
        try:
            parsed = parse_api_row(row)
            if not parsed:
                continue
            uid = parsed.get("id")
            if not uid or uid in seen:
                continue
            # Add to seen early to avoid duplicates during processing crash
            seen.add(uid)
            msg_text = format_for_telegram(parsed)
            for cid in CHAT_IDS_LIST:
                send_to_telegram(cid, msg_text)
                time.sleep(0.15)
            new_count += 1
            # small delay between rows to reduce burst
            time.sleep(0.2)
        except Exception:
            logger.exception("Error processing row")
    if new_count:
        logger.info("Sent %d new messages.", new_count)
        # persist seen
        save_seen(seen)

def main_loop():
    logger.info("Starting OTP forwarder (JSON API) with login support.")
    logger.info("Login URL: %s", LOGIN_URL)
    logger.info("Data API URL: %s", DATA_API_URL)
    logger.info("Polling every %s seconds", POLL_INTERVAL)

    # initial ensure session
    ensure_session()

    try:
        while True:
            try:
                poll_and_forward_once()
            except Exception:
                logger.exception("Unhandled exception in poll cycle")
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        logger.info("Interrupted by user. Saving state and exiting.")
        save_seen(seen)

if __name__ == "__main__":
    # validation
    if not BOT_TOKEN or not CHAT_IDS_LIST:
        logger.error("BOT_TOKEN and CHAT_IDS environment variables are required. Exiting.")
        raise SystemExit(1)
    if not USERNAME or not PASSWORD:
        logger.error("USERNAME and PASSWORD environment variables are required for login. Exiting.")
        raise SystemExit(1)

    main_loop()
