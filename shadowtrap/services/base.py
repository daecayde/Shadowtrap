"""Base class for all honeypot services."""

import asyncio
import uuid
from abc import ABC, abstractmethod
from collections import defaultdict
from time import time
from typing import Optional


class BaseHoneypot(ABC):
    """Abstract base class for honeypot service implementations."""

    SERVICE_NAME = "base"

    def __init__(self, config: dict, logger, geoip, alerter):
        self.config = config
        self.logger = logger
        self.geoip = geoip
        self.alerter = alerter
        self.bind = config.get("bind", "0.0.0.0")
        self.port = config.get("port", 0)
        self._connections = defaultdict(list)  # IP -> [timestamps]
        self._max_conn = config.get("max_connections_per_ip", 10)
        self._rate_window = config.get("rate_limit_window", 60)

    @abstractmethod
    async def start(self) -> asyncio.AbstractServer:
        """Start the honeypot service. Must return an asyncio server."""
        pass

    def new_session(self) -> str:
        """Generate a unique session ID."""
        return str(uuid.uuid4())

    def check_rate_limit(self, ip: str) -> bool:
        """Check if an IP has exceeded the connection rate limit.

        Returns:
            True if connection should be allowed, False if rate-limited.
        """
        now = time()
        # Clean old entries
        self._connections[ip] = [
            t for t in self._connections[ip] if now - t < self._rate_window
        ]
        if len(self._connections[ip]) >= self._max_conn:
            self.log_event("rate_limited", src_ip=ip)
            return False
        self._connections[ip].append(now)
        return True

    def log_event(self, event_type: str, **kwargs):
        """Log an event with GeoIP enrichment."""
        src_ip = kwargs.get("src_ip", "")
        if src_ip:
            kwargs["geo"] = self.geoip.lookup(src_ip)

        event_id = self.logger.log_event(
            service=self.SERVICE_NAME,
            event_type=event_type,
            **kwargs,
        )

        # Trigger alerts
        self.alerter.send_alert({
            "service": self.SERVICE_NAME,
            "event_type": event_type,
            **kwargs,
        })

        return event_id
