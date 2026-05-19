"""CLI entry point for ShadowTrap."""

import asyncio
import signal
import sys
import click
import yaml
from pathlib import Path
from shadowtrap.core.engine import HoneypotEngine
from shadowtrap.core.logger import TrapLogger

@click.command()
@click.option("--config", "-c", default="config/shadowtrap.yml", help="Path to config file")
@click.option("--service", "-s", default=None, help="Run a single service (ssh, http, ftp, smtp, telnet)")
@click.option("--port", "-p", default=None, type=int, help="Override port for single service mode")
@click.option("--verbose", "-v", is_flag=True, help="Enable debug logging")
def main(config, service, port, verbose):
    """ShadowTrap - Modular Honeypot Framework"""

    config_path = Path(config)
    if not config_path.exists():
        click.echo(f"[!] Config file not found: {config}")
        click.echo("[*] Copy config/shadowtrap.example.yml to config/shadowtrap.yml")
        sys.exit(1)

    with open(config_path, "r") as f:
        cfg = yaml.safe_load(f)

    if verbose:
        cfg["general"]["verbosity"] = "debug"

    if service and port:
        cfg["services"] = {
            service: {**cfg["services"].get(service, {}), "enabled": True, "port": port}
        }
    elif service:
        for svc in cfg["services"]:
            cfg["services"][svc]["enabled"] = (svc == service)

    logger = TrapLogger(cfg["general"])
    engine = HoneypotEngine(cfg, logger)

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)

    def shutdown(sig, frame):
        click.echo("\n[*] Shutting down ShadowTrap...")
        loop.run_until_complete(engine.shutdown())
        sys.exit(0)

    signal.signal(signal.SIGINT, shutdown)
    signal.signal(signal.SIGTERM, shutdown)

    click.echo(r"""
   _____ __              __              ______                
  / ___// /_  ____ _____/ /___ _      __/_  __/________ _____ 
  \__ \/ __ \/ __ `/ __  / __ \ | /| / / / / / ___/ __ `/ __ \
 ___/ / / / / /_/ / /_/ / /_/ / |/ |/ / / / / /  / /_/ / /_/ /
/____/_/ /_/\__,_/\__,_/\____/|__/|__/ /_/ /_/   \__,_/ .___/ 
                                                      /_/      
    """)
    click.echo(f"[*] ShadowTrap v1.4.0 starting...")
    click.echo(f"[*] Config: {config_path.resolve()}")

    try:
        loop.run_until_complete(engine.start())
        loop.run_forever()
    except KeyboardInterrupt:
        shutdown(None, None)

if __name__ == "__main__":
    main()
