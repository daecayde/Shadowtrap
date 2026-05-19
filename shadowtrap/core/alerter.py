"""Webhook-based alert system for notable honeypot events."""

import json
import time
import threading
from typing import Optional
import requests


class AlertManager:
    """Send alerts via webhooks when notable events occur."""

    def __init__(self, config: dict, logger):
        self.enabled = config.get("enabled", False)
        self.webhook_url = config.get("webhook_url", "")
        self.telegram_token = config.get("telegram_bot_token", "")
        self.telegram_chat = config.get("telegram_chat_id", "")
        self.alert_on = set(config.get("alert_on", []))
        self.cooldown = config.get("cooldown", 300)
        self.logger = logger
        self._last_alert: dict = {}  # rate limiting per event type

    def should_alert(self, event_type: str, src_ip: str) -> bool:
        """Check if an alert should fire (respecting cooldown)."""
        if not self.enabled or event_type not in self.alert_on:
            return False

        key = f"{event_type}:{src_ip}"
        now = time.time()
        if key in self._last_alert:
            if now - self._last_alert[key] < self.cooldown:
                return False

        self._last_alert[key] = now
        return True

    def send_alert(self, event: dict):
        """Send alert in a background thread to avoid blocking."""
        if not self.should_alert(event.get("event_type", ""), event.get("src_ip", "")):
            return

        thread = threading.Thread(target=self._dispatch, args=(event,), daemon=True)
        thread.start()

    def _dispatch(self, event: dict):
        """Dispatch alert to configured channels."""
        message = self._format_message(event)

        if self.webhook_url:
            self._send_webhook(message)

        if self.telegram_token and self.telegram_chat:
            self._send_telegram(message)

    def _format_message(self, event: dict) -> str:
        """Format event into human-readable alert message."""
        geo = event.get("geo", {})
        lines = [
            f"🚨 **ShadowTrap Alert**",
            f"**Service:** {event.get('service', 'unknown').upper()}",
            f"**Event:** {event.get('event_type', 'unknown')}",
            f"**Source:** {event.get('src_ip', 'unknown')}:{event.get('src_port', '?')}",
            f"**Location:** {geo.get('city', '?')}, {geo.get('country', '?')}",
            f"**Time:** {event.get('timestamp', 'unknown')}",
        ]

        if event.get("username"):
            lines.append(f"**Username:** `{event['username']}`")
        if event.get("password"):
            lines.append(f"**Password:** `{event['password']}`")
        if event.get("payload"):
            lines.append(f"**Payload:** ```{event['payload'][:200]}```")

        return "\n".join(lines)

    def _send_webhook(self, message: str):
        """Send alert to Slack/Discord webhook."""
        try:
            payload = {"content": message, "text": message}
            requests.post(self.webhook_url, json=payload, timeout=10)
        except Exception as e:
            self.logger.json_logger.error(f"Webhook alert failed: {e}")

    def _send_telegram(self, message: str):
        """Send alert via Telegram bot."""
        try:
            url = f"https://api.telegram.org/bot{self.telegram_token}/sendMessage"
            payload = {
                "chat_id": self.telegram_chat,
                "text": message.replace("**", "*"),
                "parse_mode": "Markdown",
            }
            requests.post(url, json=payload, timeout=10)
        except Exception as e:
            self.logger.json_logger.error(f"Telegram alert failed: {e}")
