"""
scripts/setup_telegram.py — Register Telegram Webhook
========================================================
Run this once after deployment to tell Telegram where to send updates.

Usage:
    python scripts/setup_telegram.py

Requires in .env:
    TELEGRAM_BOT_TOKEN=<from @BotFather>
    TELEGRAM_WEBHOOK_SECRET=<your random secret>
    TELEGRAM_WEBHOOK_URL=https://your-public-domain.com
"""
import asyncio, os, sys
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from integrations.telegram_integration import register_webhook, get_webhook_info

async def main():
    print("Registering Telegram webhook...")
    result = await register_webhook()
    print(f"Registration result: {result}")
    print("\nCurrent webhook status:")
    info = await get_webhook_info()
    print(info)

if __name__ == "__main__":
    asyncio.run(main())
