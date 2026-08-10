#!/usr/bin/env python3
"""Register or inspect the Telegram webhook for the Vercel backend."""

import argparse
import json
import os
import sys
import urllib.error
import urllib.request


def telegram_call(token, method, payload=None):
    request = urllib.request.Request(
        f"https://api.telegram.org/bot{token}/{method}",
        data=json.dumps(payload or {}).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        with urllib.request.urlopen(request, timeout=30) as response:
            data = json.loads(response.read().decode("utf-8"))
    except urllib.error.HTTPError as exc:
        try:
            details = json.loads(exc.read().decode("utf-8"))
            message = details.get("description")
        except (ValueError, UnicodeDecodeError):
            message = None
        raise RuntimeError(message or f"Telegram returned HTTP {exc.code}") from exc
    except (ValueError, UnicodeDecodeError) as exc:
        raise RuntimeError("Telegram returned an invalid response") from exc
    if not data.get("ok"):
        raise RuntimeError(data.get("description") or "Telegram API request failed")
    return data.get("result")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--backend-url",
        default=os.environ.get("BACKEND_URL", "https://hadowken-api.vercel.app"),
        help="Backend origin without a trailing slash",
    )
    parser.add_argument(
        "--token",
        default=os.environ.get("TELEGRAM_BOT_TOKEN"),
        help="BotFather token (or set TELEGRAM_BOT_TOKEN)",
    )
    parser.add_argument(
        "--secret",
        default=os.environ.get("TELEGRAM_WEBHOOK_SECRET"),
        help="Webhook secret configured in Vercel (or set TELEGRAM_WEBHOOK_SECRET)",
    )
    parser.add_argument("--info", action="store_true", help="Only show current webhook status")
    args = parser.parse_args()

    if not args.token:
        parser.error("Provide --token or set TELEGRAM_BOT_TOKEN")

    if not args.info:
        if not args.secret:
            parser.error("Provide --secret or set TELEGRAM_WEBHOOK_SECRET")
        webhook_url = f"{args.backend_url.rstrip('/')}/api/telegram/webhook"
        result = telegram_call(
            args.token,
            "setWebhook",
            {
                "url": webhook_url,
                "secret_token": args.secret,
                "allowed_updates": ["message"],
                "drop_pending_updates": True,
            },
        )
        print(f"Webhook registration result: {result}")
        telegram_call(
            args.token,
            "setMyCommands",
            {
                "commands": [
                    {"command": "start", "description": "Show bot instructions"},
                    {"command": "tv", "description": "Link TV using an 8-digit code"},
                    {"command": "random", "description": "Get prioritized random login links"},
                    {"command": "status", "description": "Check bot status and limits"},
                    {"command": "help", "description": "Show upload instructions"},
                ]
            },
        )
        print("Bot commands registered: /start, /tv, /random, /status, /help")

    info = telegram_call(args.token, "getWebhookInfo")
    # Telegram does not return the bot token or webhook secret here.
    print(json.dumps(info, indent=2))
    if info.get("last_error_message"):
        return 1
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except (urllib.error.URLError, RuntimeError) as exc:
        print(f"Setup failed: {exc}", file=sys.stderr)
        raise SystemExit(1)
