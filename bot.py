#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
IMS SMS dashboard forwarder
Target: https://imssms.org (client SMSDashboard)
- Auto-detects simple math captcha on login page and solves it
- Attempts to discover dashboard JSON/XHR endpoint if unknown
- MongoDB dedupe + local JSON fallback
- Configurable via environment variables (IMSSMS_ prefix)
"""

import os, time, json, logging, re, tempfile, requests
from hashlib import sha1
from datetime import datetime, timedelta, timezone
from bs4 import BeautifulSoup
from pymongo import MongoClient

# === CONFIG ===
BOT_TOKEN = os.getenv("IMSSMS_BOT_TOKEN") or os.getenv("BOT_TOKEN")
CHAT_IDS = os.getenv("IMSSMS_CHAT_IDS", os.getenv("CHAT_IDS", ""))
USERNAME = os.getenv("IMSSMS_USERNAME") or os.getenv("USERNAME")
PASSWORD = os.getenv("IMSSMS_PASSWORD") or os.getenv("PASSWORD")
SITE_BASE = os.getenv("IMSSMS_SITE_BASE", "https://imssms.org").rstrip("/")
LOGIN_PATH = os.getenv("IMSSMS_LOGIN_PATH", "/login")
DASH_PATH = os.getenv("IMSSMS_DASH_PATH", "/client/SMSDashboard")
# If you already know a data API path, set it (example: /client/res/data_smscdr.php)
KNOWN_DATA_API = os.getenv("IMSSMS_DATA_API_PATH", "")  

MONGO_URI = os.getenv("IMSSMS_MONGO_URI", os.getenv("MONGO_URI", ""))
POLL_INTERVAL = float(os.getenv("IMSSMS_POLL_INTERVAL", os.getenv("POLL_INTERVAL", "2")))
REQUEST_TIMEOUT = float(os.getenv("IMSSMS_REQUEST_TIMEOUT", os.getenv("REQUEST_TIMEOUT", "15")))
STATE_FILE = os.getenv("IMSSMS_STATE_FILE", "seen_imssms.json")

LOGIN_URL = f"{SITE_BASE}{LOGIN_PATH}"
DASH_URL = f"{SITE_BASE}{DASH_PATH}"
DATA_API_CANDIDATES = [
    KNOWN_DATA_API,
    "/client/res/data_smscdr.php",
    "/res/data_smscdr.php",
    "/client/agent/res/data_smscdr.php",
    "/client/res/data.php",
    "/res/data.php",
    "/client/res/get_sms.php",
]

CHAT_IDS_LIST = [c.strip() for c in CHAT_IDS.split(",") if c.strip()]
TELEGRAM_API = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"

# === LOGGING ===
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(message)s")
log = logging.getLogger("IMS-OTP-Bot")

# === REGEX ===
OTP_CODE = re.compile(r'\b\d{3,8}\b')
MATH_Q_RE = re.compile(r'What is\s*([0-9]+)\s*([+\-xX*\/])\s*([0-9]+)\s*=?', re.I)
JSON_API_RE = re.compile(r'["\'](?P<path>/(?:[a-zA-Z0-9_\-/]+data[^\s"\'<>]*))["\']')

# === MongoDB ===
mongo_coll = None
if MONGO_URI:
    try:
        client = MongoClient(MONGO_URI)
        db = client["otpdb"]
        mongo_coll = db.get_collection("imssms_otps")
        mongo_coll.create_index("id", unique=True)
        log.info("✅ MongoDB connected")
    except Exception as e:
        log.error("MongoDB connect fail: %s", e)

# === Seen cache ===
def load_seen():
    if os.path.exists(STATE_FILE):
        try:
            with open(STATE_FILE) as f:
                return set(json.load(f))
        except Exception:
            return set()
    return set()

def save_seen(seen):
    try:
        fd, tmp = tempfile.mkstemp()
        with os.fdopen(fd, "w") as f:
            json.dump(list(seen), f)
        os.replace(tmp, STATE_FILE)
    except Exception:
        pass

seen = load_seen()

# === Session login ===
session = requests.Session()
session.headers.update({"User-Agent": "Mozilla/5.0 (compatible; IMS-OTP-Bot/1.0)"})

def solve_math_question(text):
    """
    Parse and solve a simple math question like 'What is 9 + 7 = ?'
    Supports +, -, *, / (x or X interpreted as *)
    """
    m = MATH_Q_RE.search(text or "")
    if not m:
        return None
    a, op, b = m.group(1), m.group(2), m.group(3)
    a = int(a); b = int(b)
    if op in ("+",):
        return str(a + b)
    if op in ("-",):
        return str(a - b)
    if op in ("x", "X", "*"):
        return str(a * b)
    if op in ("/",):
        # integer division if divides evenly else floor
        return str(a // b if b != 0 else 0)
    return None

def login():
    if not USERNAME or not PASSWORD:
        log.error("No USERNAME/PASSWORD set for IMS bot")
        return False
    try:
        r = session.get(LOGIN_URL, timeout=REQUEST_TIMEOUT)
        soup = BeautifulSoup(r.text or "", "html.parser")
        # find token field if exists
        token_input = soup.find("input", {"name": "_token"})
        payload = {"username": USERNAME, "password": PASSWORD}
        if token_input and token_input.get("value"):
            payload["_token"] = token_input.get("value")
        # try to find a math question on the page and answer it
        page_text = soup.get_text(" ", strip=True)
        math_answer = solve_math_question(page_text)
        if math_answer is not None:
            # common field names: "captcha", "answer", "math" - try a few
            # we'll send as 'answer' and 'captcha' to be safe
            payload.update({"answer": math_answer, "captcha": math_answer})
            log.debug("Found math captcha, answer=%s", math_answer)
        resp = session.post(LOGIN_URL, data=payload, timeout=REQUEST_TIMEOUT, allow_redirects=True)
        if resp.status_code in (200, 302):
            log.info("✅ Login attempted (status %s)", resp.status_code)
            return True
        log.warning("Login returned status %s", resp.status_code)
        return True
    except Exception as e:
        log.error("Login fail: %s", e)
        return False

# === Discover data API ===
def discover_data_api():
    # If user provided a known path, prefer that
    if KNOWN_DATA_API:
        cand = KNOWN_DATA_API
        return cand if cand.startswith("/") else f"/{cand.lstrip('/')}"
    try:
        r = session.get(DASH_URL, timeout=REQUEST_TIMEOUT)
        text = r.text or ""
        # search for obvious JSON endpoints in JS
        for m in JSON_API_RE.finditer(text):
            path = m.group("path")
            # simple heuristic: path containing 'data' or 'res' or 'sms' likely candidate
            if any(k in path.lower() for k in ("data", "res", "sms", "cdr", "aaData")):
                log.info("🔎 Discovered candidate data API: %s", path)
                return path
        # fallback to common candidate list
        for p in DATA_API_CANDIDATES:
            if not p:
                continue
            full = f"{SITE_BASE}{p}"
            try:
                rr = session.get(full, timeout=6)
                # look for JSON or expected pattern
                if rr.ok and ("aaData" in (rr.text or "") or rr.headers.get("Content-Type","").startswith("application/json")):
                    log.info("🔎 Working data API found: %s", p)
                    return p
            except Exception:
                pass
    except Exception as e:
        log.warning("Discover API fail: %s", e)
    log.warning("No data API discovered automatically; you can set IMSSMS_DATA_API_PATH env var")
    return None

# === Fetch SMS ===
def fetch_sms(data_api_path):
    if not data_api_path:
        return []
    full = data_api_path if data_api_path.startswith("http") else f"{SITE_BASE}{data_api_path}"
    now = datetime.now(timezone.utc)
    f1 = (now - timedelta(minutes=5)).strftime("%Y-%m-%d %H:%M:%S")
    f2 = now.strftime("%Y-%m-%d %H:%M:%S")
    try:
        r = session.get(full, params={"fdate1": f1, "fdate2": f2}, timeout=REQUEST_TIMEOUT)
        # if server returns HTML, maybe session expired — trigger re-login
        if r.text and r.text.strip().startswith("<"):
            log.info("Fetch returned HTML — re-login and skip this cycle")
            login()
            return []
        # try to decode JSON
        payload = None
        try:
            payload = r.json()
        except Exception:
            # sometimes response is wrapped or not JSON — try to find aaData substring
            if "aaData" in (r.text or ""):
                # naive extraction - not guaranteed; return empty so we don't crash
                return []
            return []
        data = payload.get("aaData", []) if isinstance(payload, dict) else []
        return data
    except Exception as e:
        log.warning("Fetch fail: %s", e)
        return []

# === Parse ===
def parse_row(row):
    try:
        # Most IMS dashboards use aaData rows: [time, operator, number, service, client, msg, ...]
        ts, operator, number, service, client, msg = row[:6]
    except Exception:
        return None
    uid = sha1(f"{number}|{msg}|{ts}".encode()).hexdigest()
    m = OTP_CODE.search(msg or "")
    code = m.group(0) if m else "N/A"
    return {
        "id": uid,
        "number": number.strip(),
        "msg": (msg or "").strip(),
        "time": ts,
        "operator": operator or "Unknown",
        "code": code,
        "site": SITE_BASE
    }

def format_msg(e):
    return (
        f"✅ New OTP Received\n\n"
        f"🌐 Site: {e.get('site')}\n"
        f"🕰️ Time: {e['time']}\n"
        f"📞 Number: {e['number']}\n"
        f"🔑 OTP Code: {e['code']}\n"
        f"🌍 Operator: {e['operator']}\n\n"
        f"💬 Full Message:\n{e['msg']}"
    )

# === Telegram ===
def send_tg(text):
    if not CHAT_IDS_LIST:
        log.warning("No CHAT_IDS configured; skipping telegram send")
        return
    for cid in CHAT_IDS_LIST:
        try:
            requests.post(TELEGRAM_API, data={"chat_id": cid, "text": text[:4000]}, timeout=10)
        except Exception:
            pass

# === Main Loop ===
def main():
    if not BOT_TOKEN or not CHAT_IDS_LIST:
        log.error("Missing BOT_TOKEN or CHAT_IDS — set IMSSMS_BOT_TOKEN and IMSSMS_CHAT_IDS (comma sep)")
        return
    login()
    data_api = discover_data_api()
    if not data_api:
        log.info("If discover failed, set IMSSMS_DATA_API_PATH to the correct endpoint (e.g. /client/res/data_smscdr.php)")
    log.info("🚀 IMS bot started polling %s (api=%s)", SITE_BASE, data_api)
    while True:
        rows = fetch_sms(data_api)
        for row in reversed(rows):
            e = parse_row(row)
            if not e:
                continue
            if e["id"] in seen:
                continue
            if mongo_coll and mongo_coll.find_one({"id": e["id"]}):
                seen.add(e["id"])
                continue
            text = format_msg(e)
            send_tg(text)
            seen.add(e["id"])
            if mongo_coll:
                try:
                    mongo_coll.insert_one(e)
                except Exception:
                    pass
            save_seen(seen)
            log.info("Forwarded %s (%s)", e["number"], e["code"])
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
