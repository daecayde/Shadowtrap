"""Live terminal dashboard for monitoring honeypot activity."""

import json
import time
import os
from pathlib import Path
from collections import Counter
from datetime import datetime

try:
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.text import Text
    RICH_AVAILABLE = True
except ImportError:
    RICH_AVAILABLE = False


def parse_events(log_path: str = "logs/events.json") -> list:
    """Parse JSON log file into event list."""
    events = []
    path = Path(log_path)
    if not path.exists():
        return events

    with open(path, "r") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                events.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return events


def build_dashboard(events: list) -> Layout:
    """Build the Rich dashboard layout."""
    console = Console()
    layout = Layout()

    # Stats
    total = len(events)
    unique_ips = len(set(e.get("src_ip", "") for e in events if e.get("src_ip")))
    login_attempts = sum(1 for e in events if e.get("event_type") == "login_attempt")
    commands = sum(1 for e in events if e.get("event_type") == "command_execution")

    stats_text = Text()
    stats_text.append(f"  Total Events: ", style="bold")
    stats_text.append(f"{total}\n", style="bold cyan")
    stats_text.append(f"  Unique IPs: ", style="bold")
    stats_text.append(f"{unique_ips}\n", style="bold yellow")
    stats_text.append(f"  Login Attempts: ", style="bold")
    stats_text.append(f"{login_attempts}\n", style="bold red")
    stats_text.append(f"  Commands Captured: ", style="bold")
    stats_text.append(f"{commands}", style="bold green")

    stats_panel = Panel(stats_text, title="[bold]Overview[/bold]", border_style="blue")

    # Top IPs
    ip_counter = Counter(e.get("src_ip", "unknown") for e in events if e.get("src_ip"))
    ip_table = Table(title="Top Attacker IPs", show_header=True, header_style="bold magenta")
    ip_table.add_column("IP Address", style="cyan")
    ip_table.add_column("Count", justify="right", style="red")
    ip_table.add_column("Country", style="yellow")

    for ip, count in ip_counter.most_common(10):
        country = "N/A"
        for e in events:
            if e.get("src_ip") == ip and e.get("geo", {}).get("country"):
                country = e["geo"]["country"]
                break
        ip_table.add_row(ip, str(count), country)

    # Top credentials
    cred_counter = Counter()
    for e in events:
        if e.get("event_type") == "login_attempt" and e.get("username"):
            cred = f"{e.get('username', '')}:{e.get('password', '')}"
            cred_counter[cred] += 1

    cred_table = Table(title="Top Credentials", show_header=True, header_style="bold magenta")
    cred_table.add_column("Username:Password", style="red")
    cred_table.add_column("Count", justify="right", style="cyan")

    for cred, count in cred_counter.most_common(10):
        cred_table.add_row(cred, str(count))

    # Recent events
    recent_table = Table(title="Recent Events", show_header=True, header_style="bold magenta")
    recent_table.add_column("Time", style="dim")
    recent_table.add_column("Service", style="green")
    recent_table.add_column("Event", style="yellow")
    recent_table.add_column("Source IP", style="cyan")
    recent_table.add_column("Details", style="white")

    for e in events[-15:]:
        ts = e.get("timestamp", "")[:19]
        service = e.get("service", "?").upper()
        event_type = e.get("event_type", "?")
        src_ip = e.get("src_ip", "?")
        details = e.get("username", e.get("payload", ""))[:40] if e.get("username") or e.get("payload") else ""
        recent_table.add_row(ts, service, event_type, src_ip, str(details))

    return stats_panel, ip_table, cred_table, recent_table


def main():
    """Run the live dashboard."""
    if not RICH_AVAILABLE:
        print("[!] Install 'rich' package: pip install rich")
        return

    console = Console()

    console.print("[bold blue]ShadowTrap Dashboard[/bold blue]", justify="center")
    console.print("Press Ctrl+C to exit\n", style="dim", justify="center")

    try:
        with Live(console=console, refresh_per_second=0.5) as live:
            while True:
                events = parse_events()
                panels = build_dashboard(events)

                from rich.console import Group
                live.update(Group(*panels))
                time.sleep(2)
    except KeyboardInterrupt:
        console.print("\n[bold]Dashboard stopped.[/bold]")


if __name__ == "__main__":
    main()
