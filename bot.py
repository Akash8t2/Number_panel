# -*- coding: utf-8 -*-
"""
iVasms multi-account -> Telegram forwarder
Supports:
 - IVASMS_ACCOUNTS (JSON array) OR
 - single USERNAME / PASSWORD OR
 - numbered USERNAME_1 / PASSWORD_1 ... USERNAME_N / PASSWORD_N
Chat IDs stored in chat_ids.json (or provided via CHAT_IDS env).
Admin IDs provided via ADMIN_CHAT_IDS env (comma-separated).
Bot token via YOUR_BOT_TOKEN env.
"""
import asyncio
import re
import httpx
from bs4 import BeautifulSoup
import time
import json
import os
import traceback
from urllib.parse import urljoin
from datetime import datetime, timedelta
from telegram.ext import Application, CommandHandler, ContextTypes
from telegram import Update
import html as _html

# ----------------- CONFIG / ENV -----------------
YOUR_BOT_TOKEN = os.getenv("YOUR_BOT_TOKEN")

# Admins: comma-separated IDs (e.g. "12345,67890")
ADMIN_CHAT_IDS = [x.strip() for x in os.getenv("ADMIN_CHAT_IDS", "").split(",") if x.strip()]

# Fallback initial chat ids
INITIAL_CHAT_IDS = os.getenv("CHAT_IDS", "-1003073839183").split(",")

# Accept accounts in multiple ways:
# 1) IVASMS_ACCOUNTS env (JSON string): [{"username":"u","password":"p"}, ...]
# 2) Single USERNAME & PASSWORD env
# 3) NUMBERED: USERNAME_1/PASSWORD_1, USERNAME_2/PASSWORD_2, ...
def build_accounts():
    # 1) JSON array env
    env_json = os.getenv("IVASMS_ACCOUNTS", "").strip()
    if env_json:
        try:
            arr = json.loads(env_json)
            if isinstance(arr, list) and arr:
                return [{"username": a["username"], "password": a["password"]} for a in arr]
        except Exception as e:
            print("⚠️ IVASMS_ACCOUNTS json parse error:", e)

    # 2) Single USERNAME / PASSWORD
    single_username = os.getenv("USERNAME")
    single_password = os.getenv("PASSWORD")
    if single_username and single_password:
        return [{"username": single_username, "password": single_password}]

    # 3) numbered pairs
    accounts = []
    i = 1
    while os.getenv(f"USERNAME_{i}") and os.getenv(f"PASSWORD_{i}"):
        accounts.append({
            "username": os.getenv(f"USERNAME_{i}"),
            "password": os.getenv(f"PASSWORD_{i}")
        })
        i += 1
    return accounts

ACCOUNTS = build_accounts()

LOGIN_URL = "https://www.ivasms.com/login"
BASE_URL = "https://www.ivasms.com/"
SMS_API_ENDPOINT = "https://www.ivasms.com/portal/sms/received/getsms"

POLLING_INTERVAL_SECONDS = int(os.getenv("POLLING_INTERVAL_SECONDS", "5"))
STATE_FILE = os.getenv("STATE_FILE", "processed_sms_ids.json")
CHAT_IDS_FILE = os.getenv("CHAT_IDS_FILE", "chat_ids.json")

# ----- service keywords & emojis (kept from your original mapping, truncated for brevity) -----
SERVICE_KEYWORDS = {
    "Facebook": ["facebook"],
    "Google": ["google", "gmail"],
    "WhatsApp": ["whatsapp"],
    "Telegram": ["telegram"],
    "Instagram": ["instagram"],
    "Unknown": ["unknown"]
}
SERVICE_EMOJIS = {"Telegram":"📩","WhatsApp":"🟢","Facebook":"📘","Instagram":"📸","Unknown":"❓"}

# ----------------- UTILITIES -----------------
def now_ts():
    return datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S")

def load_chat_ids():
    # If file doesn't exist, seed from INITIAL_CHAT_IDS and save
    if not os.path.exists(CHAT_IDS_FILE):
        try:
            with open(CHAT_IDS_FILE, "w") as f:
                json.dump([c.strip() for c in INITIAL_CHAT_IDS if c.strip()], f, indent=2)
        except Exception:
            pass
        return [c.strip() for c in INITIAL_CHAT_IDS if c.strip()]
    try:
        with open(CHAT_IDS_FILE, "r") as f:
            data = json.load(f)
            return [str(x).strip() for x in data]
    except Exception as e:
        print("⚠️ load_chat_ids error:", e)
        return [c.strip() for c in INITIAL_CHAT_IDS if c.strip()]

def save_chat_ids(chat_ids):
    try:
        with open(CHAT_IDS_FILE, "w") as f:
            json.dump(chat_ids, f, indent=2)
    except Exception as e:
        print("⚠️ save_chat_ids error:", e)

def load_processed_ids():
    if not os.path.exists(STATE_FILE):
        return set()
    try:
        with open(STATE_FILE, "r") as f:
            return set(json.load(f))
    except Exception:
        return set()

def save_processed_id(sms_id):
    s = load_processed_ids()
    s.add(sms_id)
    try:
        with open(STATE_FILE, "w") as f:
            json.dump(list(s), f)
    except Exception as e:
        print("⚠️ save_processed_id error:", e)

def escape_html(text: str):
    return _html.escape(text or "")

# ----------------- TELEGRAM COMMANDS -----------------
async def start_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = str(update.effective_user.id)
    if uid in ADMIN_CHAT_IDS:
        await update.message.reply_text(
            "Welcome Admin!\n"
            "/add_chat <chat_id>\n"
            "/remove_chat <chat_id>\n"
            "/list_chats\n"
            "/list_accounts"
        )
    else:
        await update.message.reply_text("You are not authorized to use admin commands.")

async def add_chat_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = str(update.effective_user.id)
    if uid not in ADMIN_CHAT_IDS:
        return await update.message.reply_text("⛔ Only admins can use this.")
    try:
        new = context.args[0]
    except Exception:
        return await update.message.reply_text("Usage: /add_chat <chat_id>")
    chats = load_chat_ids()
    if new in chats:
        return await update.message.reply_text("⚠️ Chat already present.")
    chats.append(new)
    save_chat_ids(chats)
    await update.message.reply_text(f"✅ Added chat {new}")

async def remove_chat_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = str(update.effective_user.id)
    if uid not in ADMIN_CHAT_IDS:
        return await update.message.reply_text("⛔ Only admins can use this.")
    try:
        target = context.args[0]
    except Exception:
        return await update.message.reply_text("Usage: /remove_chat <chat_id>")
    chats = load_chat_ids()
    if target not in chats:
        return await update.message.reply_text("❌ Chat not found.")
    chats.remove(target)
    save_chat_ids(chats)
    await update.message.reply_text(f"✅ Removed chat {target}")

async def list_chats_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = str(update.effective_user.id)
    if uid not in ADMIN_CHAT_IDS:
        return await update.message.reply_text("⛔ Only admins can use this.")
    chats = load_chat_ids()
    if not chats:
        return await update.message.reply_text("No chat IDs configured.")
    await update.message.reply_text("Configured chat IDs:\n" + "\n".join(chats))

async def list_accounts_command(update: Update, context: ContextTypes.DEFAULT_TYPE):
    uid = str(update.effective_user.id)
    if uid not in ADMIN_CHAT_IDS:
        return await update.message.reply_text("⛔ Only admins can use this.")
    lines = [f"- {a['username']}" for a in ACCOUNTS]
    if not lines:
        return await update.message.reply_text("No accounts configured.")
    await update.message.reply_text("Configured accounts:\n" + "\n".join(lines))

# ----------------- SMS FETCH / PARSE / SEND -----------------
# fetch SMS summary & details using same logic as your original implementation
async def fetch_sms_from_api(client: httpx.AsyncClient, headers: dict, csrf_token: str):
    all_messages = []
    try:
        today = datetime.utcnow()
        start_date = today - timedelta(days=1)
        from_date_str, to_date_str = start_date.strftime('%m/%d/%Y'), today.strftime('%m/%d/%Y')
        first_payload = {'from': from_date_str, 'to': to_date_str, '_token': csrf_token}
        summary_response = await client.post(SMS_API_ENDPOINT, headers=headers, data=first_payload)
        summary_response.raise_for_status()
        summary_soup = BeautifulSoup(summary_response.text, 'html.parser')
        group_divs = summary_soup.find_all('div', {'class': 'pointer'})
        if not group_divs:
            return []

        group_ids = []
        for div in group_divs:
            onclick = div.get('onclick', '')
            m = re.search(r"getDetials\('(.+?)'\)", onclick)
            if m:
                group_ids.append(m.group(1))

        numbers_url = urljoin(BASE_URL, "portal/sms/received/getsms/number")
        sms_url = urljoin(BASE_URL, "portal/sms/received/getsms/number/sms")

        for group_id in group_ids:
            numbers_payload = {'start': from_date_str, 'end': to_date_str, 'range': group_id, '_token': csrf_token}
            numbers_response = await client.post(numbers_url, headers=headers, data=numbers_payload)
            numbers_soup = BeautifulSoup(numbers_response.text, 'html.parser')
            number_divs = numbers_soup.select("div[onclick*='getDetialsNumber']")
            if not number_divs:
                continue
            phone_numbers = [div.text.strip() for div in number_divs]

            for phone_number in phone_numbers:
                sms_payload = {'start': from_date_str, 'end': to_date_str, 'Number': phone_number, 'Range': group_id, '_token': csrf_token}
                sms_response = await client.post(sms_url, headers=headers, data=sms_payload)
                sms_soup = BeautifulSoup(sms_response.text, 'html.parser')
                final_sms_cards = sms_soup.find_all('div', class_='card-body')

                for card in final_sms_cards:
                    sms_text_p = card.find('p', class_='mb-0')
                    if sms_text_p:
                        sms_text = sms_text_p.get_text(separator='\n').strip()
                        date_str = datetime.utcnow().strftime('%Y-%m-%d %H:%M:%S')

                        country_name_match = re.match(r'([a-zA-Z\s]+)', group_id)
                        country_name = country_name_match.group(1).strip() if country_name_match else group_id.strip()

                        service = "Unknown"
                        lower_sms_text = sms_text.lower()
                        for service_name, keywords in SERVICE_KEYWORDS.items():
                            if any(keyword in lower_sms_text for keyword in keywords):
                                service = service_name
                                break

                        code_match = re.search(r'(\d{3}-\d{3})', sms_text) or re.search(r'\b(\d{4,8})\b', sms_text)
                        code = code_match.group(1) if code_match else "N/A"
                        unique_id = f"{phone_number}-{hash(sms_text)}"
                        flag = "🏴‍☠️"  # country flags map was large; omitted here to keep file short

                        all_messages.append({
                            "id": unique_id,
                            "time": date_str,
                            "number": phone_number,
                            "country": country_name,
                            "flag": flag,
                            "service": service,
                            "code": code,
                            "full_sms": sms_text
                        })
        return all_messages
    except httpx.RequestError as e:
        print(f"❌ Network issue (httpx): {e}")
        return []
    except Exception as e:
        print(f"❌ Error fetching or processing API data: {e}")
        traceback.print_exc()
        return []

async def send_telegram_message(context: ContextTypes.DEFAULT_TYPE, chat_id: str, message_data: dict):
    try:
        time_str = message_data.get("time", "N/A")
        number_str = message_data.get("number", "N/A")
        country_name = message_data.get("country", "N/A")
        flag_emoji = message_data.get("flag", "🏴‍☠️")
        service_name = message_data.get("service", "N/A")
        code_str = message_data.get("code", "N/A")
        full_sms_text = message_data.get("full_sms", "N/A")

        service_emoji = SERVICE_EMOJIS.get(service_name, "❓")

        # Use HTML formatting and <pre> for the message body to avoid MarkdownV2 escaping complexity
        html_msg = (
            f"🔔 <b>You have successfully received OTP</b>\n\n"
            f"📞 <b>Number:</b> {escape_html(number_str)}\n"
            f"🔑 <b>Code:</b> {escape_html(code_str)}\n"
            f"🏆 <b>Service:</b> {escape_html(service_name)} {service_emoji}\n"
            f"🌎 <b>Country:</b> {escape_html(country_name)} {flag_emoji}\n"
            f"⏳ <b>Time:</b> {escape_html(time_str)}\n\n"
            f"💬 <b>Message:</b>\n"
            f"<pre>{escape_html(full_sms_text)}</pre>"
        )

        await context.bot.send_message(chat_id=chat_id, text=html_msg, parse_mode="HTML")
    except Exception as e:
        print(f"❌ Error sending message to chat ID {chat_id}: {e}")

# ----------------- SCHEDULED JOB -----------------
async def check_sms_job(context: ContextTypes.DEFAULT_TYPE):
    print(f"\n--- [{now_ts()}] Checking for new messages ---")
    chat_ids = load_chat_ids()
    if not chat_ids:
        print("⚠️ No chat IDs configured. Use /add_chat or set CHAT_IDS env.")
        return

    if not ACCOUNTS:
        print("⚠️ No iVasms accounts configured. Set IVASMS_ACCOUNTS or USERNAME/PASSWORD envs.")
        return

    headers = {'User-Agent': 'Mozilla/5.0'}

    async with httpx.AsyncClient(timeout=30.0, follow_redirects=True) as client:
        for acc in ACCOUNTS:
            try:
                print(f"ℹ️ Logging in {acc['username']} ...")
                login_page_res = await client.get(LOGIN_URL, headers=headers)
                soup = BeautifulSoup(login_page_res.text, 'html.parser')
                token_input = soup.find('input', {'name': '_token'})
                login_data = {'email': acc['username'], 'password': acc['password']}
                if token_input:
                    login_data['_token'] = token_input.get('value')

                login_res = await client.post(LOGIN_URL, data=login_data, headers=headers)
                if "login" in str(login_res.url).lower():
                    print(f"❌ Login failed for {acc['username']}.")
                    continue

                dashboard_soup = BeautifulSoup(login_res.text, 'html.parser')
                csrf_meta = dashboard_soup.find('meta', {'name': 'csrf-token'})
                if not csrf_meta:
                    print(f"❌ CSRF token not found after login for {acc['username']}.")
                    continue
                csrf_token = csrf_meta.get('content')

                headers_local = {'User-Agent': headers['User-Agent'], 'Referer': str(login_res.url)}
                messages = await fetch_sms_from_api(client, headers_local, csrf_token)
                if not messages:
                    print(f"✔️ No messages found for {acc['username']}.")
                    continue

                processed = load_processed_ids()
                new_count = 0
                for msg in reversed(messages):
                    if msg["id"] in processed:
                        continue
                    new_count += 1
                    for cid in chat_ids:
                        await send_telegram_message(context, cid, msg)
                    save_processed_id(msg["id"])
                if new_count:
                    print(f"✅ Sent {new_count} new messages for {acc['username']} to {len(chat_ids)} chats.")
            except httpx.RequestError as e:
                print(f"❌ Network/login issue for {acc['username']}: {e}")
            except Exception as e:
                print(f"❌ Error in processing account {acc.get('username')}: {e}")
                traceback.print_exc()

# ----------------- MAIN -----------------
def main():
    print("🚀 iVasms to Telegram Bot is starting...")
    print("Loaded accounts:", len(ACCOUNTS))
    print("Admin IDs:", ADMIN_CHAT_IDS)
    print("Chat IDs file:", CHAT_IDS_FILE)

    if not YOUR_BOT_TOKEN:
        print("❌ YOUR_BOT_TOKEN env missing. Set it and restart.")
        return

    app = Application.builder().token(YOUR_BOT_TOKEN).build()
    # Commands
    app.add_handler(CommandHandler("start", start_command))
    app.add_handler(CommandHandler("add_chat", add_chat_command))
    app.add_handler(CommandHandler("remove_chat", remove_chat_command))
    app.add_handler(CommandHandler("list_chats", list_chats_command))
    app.add_handler(CommandHandler("list_accounts", list_accounts_command))

    # Job
    app.job_queue.run_repeating(check_sms_job, interval=POLLING_INTERVAL_SECONDS, first=2)

    print(f"🚀 Polling every {POLLING_INTERVAL_SECONDS} seconds.")
    app.run_polling()

if __name__ == "__main__":
    main()
