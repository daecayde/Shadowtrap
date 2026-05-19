"""Structured logging with JSON and SQLite support."""

import json
import logging
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from pythonjsonlogger import jsonlogger


class TrapLogger:
    """Centralized logging for all honeypot events."""

    def __init__(self, config: dict):
        self.log_dir = Path(config.get("log_dir", "./logs"))
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.log_format = config.get("log_format", "json")
        self.db_path = config.get("db_path", "./logs/shadowtrap.db")

        # JSON file logger
        self.json_logger = logging.getLogger("shadowtrap.events")
        self.json_logger.setLevel(logging.DEBUG)

        json_handler = logging.FileHandler(self.log_dir / "events.json")
        formatter = jsonlogger.JsonFormatter(
            fmt="%(timestamp)s %(service)s %(event_type)s %(src_ip)s %(message)s",
            rename_fields={"levelname": "level"},
        )
        json_handler.setFormatter(formatter)
        self.json_logger.addHandler(json_handler)

        # Console logger
        console = logging.StreamHandler()
        console.setLevel(getattr(logging, config.get("verbosity", "info").upper()))
        console.setFormatter(logging.Formatter(
            "\033[90m%(asctime)s\033[0m [%(levelname)s] %(message)s",
            datefmt="%H:%M:%S",
        ))
        self.json_logger.addHandler(console)

        # SQLite logger
        if self.log_format in ("sqlite", "both"):
            self._init_db()

    def _init_db(self):
        """Initialize SQLite database schema."""
        conn = sqlite3.connect(self.db_path)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS events (
                id TEXT PRIMARY KEY,
                timestamp TEXT NOT NULL,
                service TEXT NOT NULL,
                event_type TEXT NOT NULL,
                src_ip TEXT,
                src_port INTEGER,
                dst_port INTEGER,
                username TEXT,
                password TEXT,
                payload TEXT,
                session_id TEXT,
                geo_country TEXT,
                geo_city TEXT,
                geo_lat REAL,
                geo_lon REAL,
                raw_data TEXT
            )
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_timestamp ON events(timestamp)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_src_ip ON events(src_ip)
        """)
        conn.execute("""
            CREATE INDEX IF NOT EXISTS idx_service ON events(service)
        """)
        conn.commit()
        conn.close()

    def log_event(self, service: str, event_type: str, **kwargs) -> str:
        """Log a honeypot event.

        Args:
            service: Service name (ssh, http, ftp, etc.)
            event_type: Type of event (login_attempt, command, request, etc.)
            **kwargs: Additional event data

        Returns:
            Event ID string
        """
        event_id = str(uuid.uuid4())
        timestamp = datetime.now(timezone.utc).isoformat()

        event = {
            "id": event_id,
            "timestamp": timestamp,
            "service": service,
            "event_type": event_type,
            **kwargs,
        }

        # Log to JSON
        self.json_logger.info(
            f"[{service.upper()}] {event_type} from {kwargs.get('src_ip', 'unknown')}",
            extra=event,
        )

        # Log to SQLite if enabled
        if self.log_format in ("sqlite", "both"):
            self._write_db(event)

        return event_id

    def _write_db(self, event: dict):
        """Write event to SQLite database."""
        try:
            conn = sqlite3.connect(self.db_path)
            geo = event.get("geo", {})
            conn.execute(
                """INSERT INTO events 
                   (id, timestamp, service, event_type, src_ip, src_port, dst_port,
                    username, password, payload, session_id,
                    geo_country, geo_city, geo_lat, geo_lon, raw_data)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    event["id"], event["timestamp"], event["service"],
                    event["event_type"], event.get("src_ip"),
                    event.get("src_port"), event.get("dst_port"),
                    event.get("username"), event.get("password"),
                    event.get("payload"), event.get("session_id"),
                    geo.get("country"), geo.get("city"),
                    geo.get("lat"), geo.get("lon"),
                    json.dumps(event),
                ),
            )
            conn.commit()
            conn.close()
        except Exception as e:
            self.json_logger.error(f"DB write failed: {e}")

    def get_stats(self) -> dict:
        """Get summary statistics from the database."""
        conn = sqlite3.connect(self.db_path)
        cursor = conn.cursor()

        stats = {}
        cursor.execute("SELECT COUNT(*) FROM events")
        stats["total_events"] = cursor.fetchone()[0]

        cursor.execute("SELECT COUNT(DISTINCT src_ip) FROM events")
        stats["unique_ips"] = cursor.fetchone()[0]

        cursor.execute(
            "SELECT service, COUNT(*) FROM events GROUP BY service ORDER BY COUNT(*) DESC"
        )
        stats["by_service"] = dict(cursor.fetchall())

        cursor.execute(
            "SELECT src_ip, COUNT(*) as c FROM events GROUP BY src_ip ORDER BY c DESC LIMIT 10"
        )
        stats["top_ips"] = dict(cursor.fetchall())

        conn.close()
        return stats
