"""Tests for the structured logging system."""

import json
import tempfile
import os
from pathlib import Path
from unittest.mock import MagicMock


class TestTrapLogger:
    """Test suite for TrapLogger."""

    def test_json_log_creation(self):
        """Test that JSON log file is created."""
        with tempfile.TemporaryDirectory() as tmpdir:
            config = {
                "log_dir": tmpdir,
                "log_format": "json",
                "verbosity": "debug",
                "db_path": os.path.join(tmpdir, "test.db"),
            }
            from shadowtrap.core.logger import TrapLogger
            logger = TrapLogger(config)

            event_id = logger.log_event(
                service="test",
                event_type="test_event",
                src_ip="192.168.1.1",
                src_port=12345,
            )

            assert event_id is not None
            assert len(event_id) == 36  # UUID

    def test_sqlite_initialization(self):
        """Test SQLite database schema creation."""
        import sqlite3

        with tempfile.TemporaryDirectory() as tmpdir:
            db_path = os.path.join(tmpdir, "test.db")
            config = {
                "log_dir": tmpdir,
                "log_format": "both",
                "verbosity": "info",
                "db_path": db_path,
            }
            from shadowtrap.core.logger import TrapLogger
            logger = TrapLogger(config)

            conn = sqlite3.connect(db_path)
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table'")
            tables = [row[0] for row in cursor.fetchall()]
            conn.close()

            assert "events" in tables
