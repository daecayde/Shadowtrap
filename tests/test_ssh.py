"""Tests for SSH honeypot service."""

import asyncio
import pytest
from unittest.mock import MagicMock, AsyncMock


class TestSSHHoneypot:
    """Test suite for the SSH honeypot."""

    def setup_method(self):
        """Set up test fixtures."""
        self.config = {
            "bind": "127.0.0.1",
            "port": 22222,
            "banner": "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6",
            "max_auth_attempts": 3,
            "emulate_shell": True,
            "recorded_commands": [
                {"uname -a": "Linux test 5.15.0 x86_64 GNU/Linux"},
                {"whoami": "root"},
            ],
        }
        self.logger = MagicMock()
        self.logger.log_event = MagicMock(return_value="test-event-id")
        self.logger.json_logger = MagicMock()
        self.geoip = MagicMock()
        self.geoip.lookup = MagicMock(return_value={
            "country": "US", "city": "Test", "lat": 0.0, "lon": 0.0
        })
        self.alerter = MagicMock()
        self.alerter.should_alert = MagicMock(return_value=False)
        self.alerter.send_alert = MagicMock()

    def test_config_parsing(self):
        """Test that SSH config is properly parsed."""
        from shadowtrap.services.ssh_trap import SSHHoneypot

        honeypot = SSHHoneypot(
            config=self.config,
            logger=self.logger,
            geoip=self.geoip,
            alerter=self.alerter,
        )
        assert honeypot.port == 22222
        assert honeypot.banner == "SSH-2.0-OpenSSH_8.9p1 Ubuntu-3ubuntu0.6"
        assert honeypot.max_auth == 3
        assert honeypot.emulate_shell is True
        assert "uname -a" in honeypot.commands

    def test_session_id_generation(self):
        """Test that unique session IDs are generated."""
        from shadowtrap.services.ssh_trap import SSHHoneypot

        honeypot = SSHHoneypot(
            config=self.config,
            logger=self.logger,
            geoip=self.geoip,
            alerter=self.alerter,
        )
        s1 = honeypot.new_session()
        s2 = honeypot.new_session()
        assert s1 != s2
        assert len(s1) == 36  # UUID format

    def test_rate_limiting(self):
        """Test that rate limiting works correctly."""
        from shadowtrap.services.ssh_trap import SSHHoneypot

        self.config["max_connections_per_ip"] = 3
        self.config["rate_limit_window"] = 60

        honeypot = SSHHoneypot(
            config=self.config,
            logger=self.logger,
            geoip=self.geoip,
            alerter=self.alerter,
        )

        # First 3 should pass
        assert honeypot.check_rate_limit("192.168.1.1") is True
        assert honeypot.check_rate_limit("192.168.1.1") is True
        assert honeypot.check_rate_limit("192.168.1.1") is True

        # 4th should be rate limited
        assert honeypot.check_rate_limit("192.168.1.1") is False

        # Different IP should still work
        assert honeypot.check_rate_limit("192.168.1.2") is True


class TestSSHCommands:
    """Test fake shell command responses."""

    def test_command_lookup(self):
        from shadowtrap.services.ssh_trap import SSHHoneypot

        config = {
            "bind": "127.0.0.1",
            "port": 22222,
            "banner": "SSH-2.0-OpenSSH_8.9",
            "max_auth_attempts": 3,
            "emulate_shell": True,
            "recorded_commands": [
                {"whoami": "root"},
                {"id": "uid=0(root)"},
            ],
        }

        logger = MagicMock()
        logger.log_event = MagicMock(return_value="id")
        logger.json_logger = MagicMock()
        geoip = MagicMock()
        geoip.lookup = MagicMock(return_value={})
        alerter = MagicMock()
        alerter.send_alert = MagicMock()

        honeypot = SSHHoneypot(config=config, logger=logger, geoip=geoip, alerter=alerter)
        assert honeypot.commands["whoami"] == "root"
        assert honeypot.commands["id"] == "uid=0(root)"
