# bot.py
import os
import time
import requests
from bs4 import BeautifulSoup
from telegram import Bot
from datetime import datetime

# === Config ===
BOT_TOKEN = os.getenv("BOT_TOKEN")
CHAT_ID = os.getenv("CHAT_ID")
URL = "http://45.82.67.20/ints/agent/SMSCDRStats"

bot = Bot(token=BOT_TOKEN)
last_seen_id = None

def fetch_messages():
    """Fetch SMS list from the website"""
    r = requests.get(URL, timeout=15)
    r.raise_for_status()
    soup = BeautifulSoup(r.text, "html.parser")

    # Example: <tr><td>ID</td><td>Number</td><td>Sender</td><td>Message</td><td>Time</td></tr>
    rows = soup.find_all("tr")
    messages = []
    for row in rows[1:]:  # skip header
        cols = row.find_all("td")
        if len(cols) >= 5:
            sms_id = cols[0].get_text(strip=True)
            number = cols[1].get_text(strip=True)
            sender = cols[2].get_text(strip=True)
            body = cols[3].get_text(strip=True)
            timestamp = cols[4].get_text(strip=True)
            messages.append({
                "id": sms_id,
                "number": number,
                "sender": sender,
                "body": body,
                "time": timestamp
            })
    return messages

def format_message(sms):
    """Make a nice Telegram message"""
    return (
        f"📩 <b>New SMS Received</b>\n\n"
        f"📱 <b>Number:</b> {sms['number']}\n"
        f"👤 <b>From:</b> {sms['sender']}\n"
        f"📝 <b>Message:</b> {sms['body']}\n"
        f"⏰ <b>Time:</b> {sms['time']}\n"
        f"🆔 <b>ID:</b> {sms['id']}"
    )

def main():
    global last_seen_id
    print("🚀 OTP Forwarder Bot started...")
    while True:
        try:
            messages = fetch_messages()
            if messages:
                latest = messages[0]  # newest SMS
                if latest["id"] != last_seen_id:
                    last_seen_id = latest["id"]
                    text = format_message(latest)
                    bot.send_message(chat_id=CHAT_ID, text=text, parse_mode="HTML")
                    print(f"✅ Forwarded SMS {latest['id']} at {datetime.now()}")
        except Exception as e:
            print("❌ Error:", e)

        time.sleep(5)  # check every 5 seconds

if __name__ == "__main__":
    main()
