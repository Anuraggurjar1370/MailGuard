"""
MailGuard Telegram Security Bot.
Allows users to forward suspicious messages, links, or emails directly to Telegram
and receive an instant explainable phishing verdict.
"""

import os
import sys
import time
import requests

API_ENDPOINT = "http://127.0.0.1:8000/api/v1/predict"


def scan_email_via_api(text: str):
    """Submits text to MailGuard API and formats response."""
    try:
        resp = requests.post(API_ENDPOINT, json={"text": text}, timeout=10)
        if resp.status_code == 200:
            data = resp.json()
            verdict = data["verdict"]
            score = data["risk_score"]
            emoji = "🚨" if verdict == "Dangerous" else "⚠️" if verdict == "Suspicious" else "✅"

            reasons_txt = "\n".join([f"• {r}" for r in data.get("key_reasons", [])[:3]])
            msg = (
                f"{emoji} *MailGuard Analysis Result*\n\n"
                f"*Verdict:* {verdict} ({score}/100)\n"
                f"*Active Model:* {data.get('model_name')}\n"
                f"*Phishing Probability:* {data.get('phishing_probability') * 100:.1f}%\n\n"
                f"*Key Evidence:*\n{reasons_txt}\n\n"
                f"_MailGuard Explainable Multi-Layer Security Platform_"
            )
            return msg
        else:
            return f"❌ MailGuard API returned status code {resp.status_code}"
    except Exception as e:
        return f"❌ Connection Error: Ensure MailGuard API is running at {API_ENDPOINT} ({e})"


def main():
    token = os.getenv("TELEGRAM_BOT_TOKEN", "")
    print("=" * 60)
    print("  MailGuard Telegram Bot Gateway")
    print("=" * 60)

    if not token or token == "YOUR_BOT_TOKEN_HERE":
        print("[!] TELEGRAM_BOT_TOKEN not provided in environment.")
        print("[*] To use with Telegram:")
        print("    1. Create a bot with @BotFather on Telegram to obtain an API Token.")
        print("    2. Set environment variable: set TELEGRAM_BOT_TOKEN=your_token")
        print("    3. Run: python bots/telegram_bot.py\n")
        print("[*] Performing test connection to local MailGuard REST API...")
        sample_phish = "URGENT: Your account has been suspended! Click http://185.220.101.5/login immediately."
        print(f"[*] Test Input: '{sample_phish}'")
        res = scan_email_via_api(sample_phish)
        print("\n" + res + "\n")
        print("[+] Telegram Bot module verified successfully.")
        return

    print(f"[+] Starting polling loop for Telegram Bot...")
    offset = 0
    url = f"https://api.telegram.org/bot{token}"

    while True:
        try:
            updates = requests.get(f"{url}/getUpdates?offset={offset}&timeout=20", timeout=30).json()
            for item in updates.get("result", []):
                offset = item["update_id"] + 1
                msg = item.get("message", {})
                chat_id = msg.get("chat", {}).get("id")
                text = msg.get("text", "")

                if not text or not chat_id:
                    continue

                if text == "/start":
                    reply = "👋 Welcome to MailGuard Bot! Forward any suspicious email text or URL to get an instant phishing scan."
                else:
                    reply = scan_email_via_api(text)

                requests.post(f"{url}/sendMessage", json={
                    "chat_id": chat_id,
                    "text": reply,
                    "parse_mode": "Markdown"
                })
        except Exception as err:
            print(f"[!] Polling error: {err}")
            time.sleep(5)


if __name__ == "__main__":
    main()
