"""Main orchestrator — starts and manages all honeypot services."""

import asyncio
from typing import Dict, Optional
from shadowtrap.core.logger import TrapLogger
from shadowtrap.core.geoip import GeoIPResolver
from shadowtrap.core.alerter import AlertManager
from shadowtrap.services.ssh_trap import SSHHoneypot
from shadowtrap.services.http_trap import HTTPHoneypot
from shadowtrap.services.ftp_trap import FTPHoneypot
from shadowtrap.services.smtp_trap import SMTPHoneypot
from shadowtrap.services.telnet_trap import TelnetHoneypot


SERVICE_MAP = {
    "ssh": SSHHoneypot,
    "http": HTTPHoneypot,
    "ftp": FTPHoneypot,
    "smtp": SMTPHoneypot,
    "telnet": TelnetHoneypot,
}


class HoneypotEngine:
    """Core engine that orchestrates all honeypot services."""

    def __init__(self, config: dict, logger: TrapLogger):
        self.config = config
        self.logger = logger
        self.geoip = GeoIPResolver(config["general"].get("geoip_db"))
        self.alerter = AlertManager(config.get("alerts", {}), logger)
        self.services: Dict[str, object] = {}
        self._servers: list = []

    async def start(self):
        """Initialize and start all enabled services."""
        services_cfg = self.config.get("services", {})

        for name, cfg in services_cfg.items():
            if not cfg.get("enabled", False):
                continue

            if name not in SERVICE_MAP:
                self.logger.json_logger.warning(f"Unknown service: {name}")
                continue

            service_class = SERVICE_MAP[name]
            service = service_class(
                config=cfg,
                logger=self.logger,
                geoip=self.geoip,
                alerter=self.alerter,
            )
            self.services[name] = service

            try:
                server = await service.start()
                self._servers.append(server)
                bind = cfg.get("bind", "0.0.0.0")
                port = cfg.get("port")
                self.logger.json_logger.info(
                    f"\033[92m[+] {name.upper()} honeypot listening on {bind}:{port}\033[0m"
                )
            except PermissionError:
                self.logger.json_logger.error(
                    f"[!] Permission denied for {name} on port {cfg.get('port')}. "
                    f"Try a port > 1024 or run with elevated privileges."
                )
            except OSError as e:
                self.logger.json_logger.error(f"[!] Failed to start {name}: {e}")

        active = len(self.services)
        if active == 0:
            self.logger.json_logger.error("[!] No services started. Check your config.")
        else:
            self.logger.json_logger.info(f"[*] {active} service(s) active. Waiting for connections...")

    async def shutdown(self):
        """Gracefully shut down all services."""
        for server in self._servers:
            server.close()
            await server.wait_closed()
        self.logger.json_logger.info("[*] All services stopped.")
