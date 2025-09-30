#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
otp_forwarder_login.py
- Logs into the IMS/iVasms-like dashboard (handles simple math captcha),
- Scrapes SMS/OTP from two dashboard pages:
    /ints/agent/SMSDashboard and /ints/agent/SMSCDRStats
- Sends nicely formatted messages to Telegram chats.
Usage:
  - Set env vars: BOT_TOKEN, CHAT_IDS (comma-separated), USERNAME, PASSWORD
  - Optional env vars: SITE_BASE, DASH_PATH, CDR_PATH, POLL_INTERVAL, STATE_FILE
  - Run: python otp_forwarder_login.py
"""

import os
import time
import json
import logging
import requests
import re
import random
import string
from datetime import datetime
from hashlib import sha1
from urllib.parse import urljoin

from bs4 import BeautifulSoup
import phonenumbers
import pycountry

# ---------------- CONFIG (env) ----------------
BOT_TOKEN = os.getenv("BOT_TOKEN")  # required
CHAT_IDS = os.getenv("CHAT_IDS", "")  # required, comma separated
USERNAME = os.getenv("USERNAME")  # required for login
PASSWORD = os.getenv("PASSWORD")  # required for login

SITE_BASE = os.getenv("SITE_BASE", "http://45.82.67.20")
DASH_PATH = os.getenv("DASH_PATH", "/ints/agent/SMSDashboard")
CDR_PATH = os.getenv("CDR_PATH", "/ints/agent/SMSCDRStats")
LOGIN_PATH = os.getenv("LOGIN_PATH", "/ints/agent/login")  # fallback, we will GET default SITE_BASE root if not present

POLL_INTERVAL = float(os.getenv("POLL_INTERVAL", "6"))  # seconds
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
CHAT_IDS_LIST = [c.strip() for c in CHAT_IDS.split(",") if c.strip()]
TELEGRAM_API_SEND = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

# ---------------- logging ----------------
logging.basicConfig(format="%(asctime)s %(levelname)s: %(message)s", level=logging.INFO)
logger = logging.getLogger("otp_forwarder_login")

# ---------------- state (seen ids) ----------------
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

# ---------------- regex / helpers ----------------
PHONE_RE = re.compile(r'(\+?\d{6,15})')
OTP_RE = re.compile(r'\b(\d{4,8})\b')
OTP_RE_ALT = re.compile(r'(\d{3}-\d{3})')

def random_tail(length=10):
    import random, string
    return ''.join(random.choices(string.ascii_letters + string.digits, k=length))

# ---------------- service & country detection ----------------
SERVICE_KEYWORDS_SMALL = {
    "Telegram": ["telegram"],
    "Facebook": ["facebook"],
    "Google": ["google", "gmail"],
    "WhatsApp": ["whatsapp"],
    "Instagram": ["instagram"],
    "Gmail": ["gmail"],
    "Netflix": ["netflix"],
    "Amazon": ["amazon"],
    "PayPal": ["paypal"],
    "Twitter": ["twitter", "x "],
}

SERVICE_EMOJIS = {
    "Telegram": "📩", "Facebook": "📘", "Google": "🔍", "WhatsApp": "💚", "Instagram": "📷",
    "Gmail": "✉️", "Netflix": "🎬", "Amazon": "🛒", "PayPal": "💰", "Twitter": "🐦", "Unknown": "❓"
}

def detect_service(text):
    if not text:
        return "Unknown"
    low = text.lower()
    for name, keys in SERVICE_KEYWORDS_SMALL.items():
        for k in keys:
            if k in low:
                return name
    return "Unknown"

def get_country(number):
    if not number:
        return "Unknown"
    try:
        pn = phonenumbers.parse(number, None)
        region = phonenumbers.region_code_for_number(pn)
        if region:
            country = pycountry.countries.get(alpha_2=region)
            if country:
                return country.name
    except Exception:
        pass
    return "Unknown"

# ---------------- login/session management ----------------
session = None
_last_login_attempt = 0
LOGIN_MIN_INTERVAL = 5  # seconds between attempted logins to avoid hammering

def compute_simple_math_answer(text):
    """
    Parse simple math question like 'What is 1 + 0 = ?' or 'What is 3 - 1 ?' etc.
    Returns computed result as string, or None if not found.
    """
    if not text:
        return None
    # find digits and operators
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
    # fallback: simple single-digit addition like "1 + 0"
    m2 = re.search(r'(\d+)\s*\+\s*(\d+)', text)
    if m2:
        return str(int(m2.group(1)) + int(m2.group(2)))
    return None

def discover_form_fields(form):
    """
    Given a BeautifulSoup form element, find likely username/password/captcha field names.
    Returns dict: {'username': name, 'password': name, 'captcha': name or None, 'token': (name,value) or None, 'action': action_url}
    """
    inputs = form.find_all("input")
    username_field = None
    password_field = None
    captcha_field = None
    token_name = None
    token_value = None

    for inp in inputs:
        itype = (inp.get("type") or "").lower()
        name = inp.get("name")
        placeholder = (inp.get("placeholder") or "").lower()
        # username detection
        if not username_field:
            if itype in ["text", "email"] or "user" in (name or "").lower() or "email" in (name or "").lower() or "username" in placeholder or "username" in (name or "").lower() or "email" in placeholder:
                username_field = name
        # password detection
        if not password_field and itype == "password":
            password_field = name
        # token detection (csrf)
        if name and (name.startswith("_token") or "csrf" in name.lower() or name.lower().startswith("token")):
            token_name = name
            token_value = inp.get("value")
        # captcha-like detection: small text input or name contains 'captcha' or placeholder contains '?'
        if not captcha_field:
            if name and ("captcha" in name.lower() or "answer" in name.lower()):
                captcha_field = name
            elif placeholder and ("?" in placeholder or "answer" in placeholder):
                captcha_field = name
            elif itype in ["text"] and (len(placeholder) < 6 and "?" in (form.get_text() or "")):
                captcha_field = name

    # if still no username/password, fallback to first text and first password or best guess
    if not username_field:
        for inp in inputs:
            if (inp.get("type") or "").lower() in ["text", "email"]:
                username_field = inp.get("name")
                break
    if not password_field:
        for inp in inputs:
            if (inp.get("type") or "").lower() == "password":
                password_field = inp.get("name")
                break

    action = form.get("action") or ""
    return {"username": username_field, "password": password_field, "captcha": captcha_field, "token": (token_name, token_value), "action": action}

def create_logged_session():
    """
    Attempts to create and return a logged-in requests.Session.
    Heuristics: finds the login form, detects field names (username/password/captcha), CSRF tokens, posts form.
    """
    global session, _last_login_attempt
    now = time.time()
    if now - _last_login_attempt < LOGIN_MIN_INTERVAL:
        return None
    _last_login_attempt = now

    if not USERNAME or not PASSWORD:
        logger.warning("USERNAME or PASSWORD not set; cannot login.")
        return None

    s = requests.Session()
    s.headers.update({"User-Agent": USER_AGENT, "Referer": SITE_BASE})
    try:
        r = s.get(LOGIN_URL, timeout=REQUEST_TIMEOUT)
    except Exception as e:
        logger.warning("Failed to GET login page: %s", e)
        return None

    if r.status_code >= 400:
        logger.warning("Login page returned status %s; trying root page instead.", r.status_code)
        try:
            r = s.get(SITE_BASE, timeout=REQUEST_TIMEOUT)
        except Exception as e:
            logger.warning("Failed to GET site root: %s", e)
            return None

    soup = BeautifulSoup(r.text, "html.parser")

    # Find a form that looks like login form
    login_form = None
    # search for forms that have password input
    for form in soup.find_all("form"):
        if form.find("input", {"type": "password"}):
            login_form = form
            break
    if login_form is None:
        # fallback: first form
        login_form = soup.find("form")
    if login_form is None:
        logger.warning("No form found on login page.")
        return None

    fields = discover_form_fields(login_form)
    username_name = fields.get("username")
    password_name = fields.get("password")
    captcha_name = fields.get("captcha")
    token_pair = fields.get("token")  # (name, value)
    action = fields.get("action") or LOGIN_URL
    post_url = urljoin(r.url, action)

    # Build payload
    payload = {}
    if username_name:
        payload[username_name] = USERNAME
    else:
        # try common names
        payload['username'] = USERNAME
        payload['email'] = USERNAME

    if password_name:
        payload[password_name] = PASSWORD
    else:
        payload['password'] = PASSWORD

    if token_pair and token_pair[0]:
        # if token value present in input, include; otherwise attempt meta
        if token_pair[1]:
            payload[token_pair[0]] = token_pair[1]
        else:
            # attempt to read meta csrf token
            meta = soup.find("meta", {"name": "csrf-token"})
            if meta and meta.get("content"):
                payload[token_pair[0]] = meta.get("content")

    # If captcha input exists, try to compute answer by looking near the input or form text
    if captcha_name:
        # try label associated with the captcha input
        captcha_input = login_form.find("input", {"name": captcha_name})
        captcha_text = ""
        if captcha_input:
            # look for previous sibling label or text
            label = None
            if captcha_input.has_attr("id"):
                label = login_form.find("label", {"for": captcha_input.get("id")})
            if not label:
                # try nearest preceding text
                prev = captcha_input.find_previous(string=True)
                if prev:
                    captcha_text = str(prev)
            else:
                captcha_text = label.get_text(separator=" ", strip=True)
        if not captcha_text:
            # fallback: full form text
            captcha_text = login_form.get_text(separator=" ", strip=True)
        answer = compute_simple_math_answer(captcha_text)
        if answer is not None:
            payload[captcha_name] = answer
            logger.info("Detected captcha question '%s' -> answer '%s'", captcha_text.strip(), answer)
        else:
            logger.warning("Could not compute captcha from text: %r . You may need to pass captcha manually.", captcha_text)

    # Send POST
    headers = {"User-Agent": USER_AGENT, "Referer": r.url}
    try:
        post_res = s.post(post_url, data=payload, headers=headers, timeout=REQUEST_TIMEOUT, allow_redirects=True)
    except Exception as e:
        logger.warning("Login POST failed: %s", e)
        return None

    post_body_low = (post_res.text or "").lower()
    # heuristics to decide if login succeeded
    if "logout" in post_body_low or "dashboard" in post_body_low or "/logout" in post_res.text or ("/login" not in str(post_res.url)):
        logger.info("Login appears successful (post url: %s)", post_res.url)
        session = s
        return session

    # Some sites redirect to same URL but contain specific dashboard markers; try to fetch dashboard
    try:
        check = s.get(DASH_URL, timeout=REQUEST_TIMEOUT)
        if check.status_code < 400 and ("sms" in (check.text or "").lower() or "received" in (check.text or "").lower()):
            logger.info("Login verified by accessing dashboard.")
            session = s
            return session
    except Exception:
        pass

    logger.warning("Login attempt did not clearly succeed. POST returned %s and url %s", post_res.status_code, post_res.url)
    return None

def ensure_session():
    global session
    if session is None:
        session = create_logged_session()
    else:
        # quick verify that session is still valid by pinging dashboard
        try:
            r = session.get(DASH_URL, timeout=REQUEST_TIMEOUT)
            body = (r.text or "").lower()
            if r.status_code >= 400 or ("login" in body and "password" in body):
                logger.info("Session invalid or expired; re-creating session.")
                session = create_logged_session()
        except Exception:
            logger.info("Session probe failed; will re-login next cycle.")
            session = create_logged_session()
    return session

# ---------------- fetching & parsing SMS ----------------
def http_get_with_session(url):
    """
    Uses logged-in session if available; will attempt to login if not.
    Falls back to unauthenticated GET if login not possible.
    """
    s = ensure_session()
    headers = {"User-Agent": USER_AGENT}
    if s:
        try:
            r = s.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
            # if we got redirected to login page => session expired
            if r.status_code < 400 and not ("login" in (r.text or "").lower() and "password" in (r.text or "").lower()):
                return r.text
            else:
                logger.info("Session page looks like login; clearing session.")
                # clear session so next call triggers re-login
                clear_session()
                # try unauthenticated as fallback
        except Exception as e:
            logger.warning("Session GET failed: %s", e)
            clear_session()
    # fallback unauthenticated
    try:
        r = requests.get(url, headers=headers, timeout=REQUEST_TIMEOUT)
        r.raise_for_status()
        return r.text
    except Exception as e:
        logger.warning("Unauthenticated GET failed for %s: %s", url, e)
        return ""

def clear_session():
    global session
    try:
        if session:
            session.close()
    except Exception:
        pass
    session = None

def extract_messages_from_html(html):
    """
    Heuristic HTML parsing: looks for table rows, card elements, paragraphs.
    Returns list of dicts: {'id','number','text','code'}
    """
    out = []
    if not html:
        return out
    soup = BeautifulSoup(html, "html.parser")

    # Search table rows first
    for tr in soup.find_all("tr"):
        text = tr.get_text(separator="\n", strip=True)
        if not text or len(text) < 6:
            continue
        phones = PHONE_RE.findall(text)
        phone = phones[0] if phones else ""
        code_search = OTP_RE_ALT.search(text) or OTP_RE.search(text)
        code = code_search.group(1) if code_search else ""
        uid = sha1((phone + "|" + text).encode("utf-8")).hexdigest()
        out.append({"id": uid, "number": phone, "text": text, "code": code})

    # Search for card-like divs
    card_selectors = ['div.card', 'div.panel', 'div.sms', 'div.message', 'div.col']
    for sel in card_selectors:
        for card in soup.select(sel):
            text = card.get_text(separator="\n", strip=True)
            if not text or len(text) < 6:
                continue
            phones = PHONE_RE.findall(text)
            phone = phones[0] if phones else ""
            code_search = OTP_RE_ALT.search(text) or OTP_RE.search(text)
            code = code_search.group(1) if code_search else ""
            uid = sha1((phone + "|" + text).encode("utf-8")).hexdigest()
            out.append({"id": uid, "number": phone, "text": text, "code": code})

    # Fallback: p, li
    if not out:
        for el in soup.find_all(["p", "li", "div"]):
            text = el.get_text(separator="\n", strip=True)
            if not text or len(text) < 12:
                continue
            phones = PHONE_RE.findall(text)
            phone = phones[0] if phones else ""
            code_search = OTP_RE_ALT.search(text) or OTP_RE.search(text)
            code = code_search.group(1) if code_search else ""
            uid = sha1((phone + "|" + text).encode("utf-8")).hexdigest()
            out.append({"id": uid, "number": phone, "text": text, "code": code})

    # dedupe preserving order
    unique = []
    seen_ids = set()
    for e in out:
        if e["id"] in seen_ids:
            continue
        seen_ids.add(e["id"])
        unique.append(e)
    return unique

# ---------------- formatting message ----------------
def format_for_telegram(entry):
    number = entry.get("number") or "N/A"
    code = entry.get("code") or "N/A"
    text = entry.get("text","").strip()
    now = datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")
    service_name = detect_service(text)
    service_emoji = SERVICE_EMOJIS.get(service_name, "❓")
    country = get_country(number)
    tail = random_tail(10)

    login_link_section = ""
    if service_name == "Telegram" and code != "N/A":
        # include t.me login link pattern (some tokens may not work, but it's the desired format)
        login_link_section = f"\nYou can also tap on this link to log in:\nhttps://t.me/login/{code}\n"

    # Construct final message exactly in style
    msg = (
        "˹𝐕𝐢𝐛𝐞ꭙ 𝐅ʟ𝐨𝐰™ ˼:\n"
        "🔔 You have successfully received OTP\n\n"
        f"📞 Number: {number}\n"
        f"🔑 Code: {code}\n"
        f"🏆 Service: {service_emoji} {service_name}\n"
        f"🌎 Country: {country}\n"
        f"⏳ Time: {now}\n\n"
        f"💬 Message:\n{text}\n"
        f"{login_link_section}\n"
        f"{tail}"
    )
    return msg

# ---------------- telegram send ----------------
def send_to_telegram(chat_id, text):
    payload = {"chat_id": chat_id, "text": text}
    try:
        r = requests.post(TELEGRAM_API_SEND, data=payload, timeout=REQUEST_TIMEOUT)
        if r.status_code != 200:
            logger.warning("Telegram send failed %s -> %s", r.status_code, r.text[:200])
    except Exception as e:
        logger.exception("Failed to send telegram message: %s", e)

# ---------------- main poll loop ----------------
def poll_once_and_forward():
    global seen
    any_sent = False
    for url in (DASH_URL, CDR_URL):
        html = http_get_with_session(url)
        if not html:
            continue
        items = extract_messages_from_html(html)
        # send oldest first
        for entry in reversed(items):
            uid = entry.get("id")
            if not uid:
                continue
            if uid in seen:
                continue
            seen.add(uid)
            msg = format_for_telegram(entry)
            logger.info("Forwarding OTP id=%s number=%s", uid[:8], entry.get("number"))
            for cid in CHAT_IDS_LIST:
                send_to_telegram(cid, msg)
                time.sleep(0.2)
            any_sent = True
            # small pause to avoid bursts
            time.sleep(0.2)
        # shrink seen if too large
        if len(seen) > MAX_SEEN:
            seen = set(list(seen)[- (MAX_SEEN // 2) :])
    if any_sent:
        save_seen(seen)

def main():
    logger.info("Starting OTP forwarder with login support.")
    if not BOT_TOKEN or not CHAT_IDS_LIST:
        logger.error("BOT_TOKEN and CHAT_IDS environment variables are required. Exiting.")
        return
    if not USERNAME or not PASSWORD:
        logger.error("USERNAME and PASSWORD environment variables are required for login. Exiting.")
        return

    logger.info("Login URL: %s", LOGIN_URL)
    logger.info("Dashboard URLs: %s , %s", DASH_URL, CDR_URL)
    logger.info("Polling every %s seconds.", POLL_INTERVAL)

    try:
        while True:
            try:
                poll_once_and_forward()
            except Exception as e:
                logger.exception("Error during poll cycle: %s", e)
            time.sleep(POLL_INTERVAL)
    except KeyboardInterrupt:
        logger.info("Interrupted by user. Saving state and exiting.")
        save_seen(seen)

if __name__ == "__main__":
    main()
