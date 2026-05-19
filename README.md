# ShadowTrap 🕸️

[!\[Python 3.9+](https://img.shields.io/badge/python-3.9+-blue.svg)](https://www.python.org/downloads/)
[!\[License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[!\[PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

**ShadowTrap** is a lightweight, modular honeypot framework designed for threat intelligence gathering and network security research. It simulates vulnerable services (SSH, HTTP, FTP, SMTP, Telnet) to attract and log attacker behavior in real time.

Built for security researchers, blue teamers, and anyone who wants to understand what's knocking on their network.

\---

## Features

* **Multi-service simulation** — SSH, HTTP, FTP, SMTP, and Telnet honeypots out of the box
* **Real-time logging** — All interactions logged with timestamps, source IPs, credentials, and payloads
* **GeoIP enrichment** — Automatic geolocation tagging of attacker IPs
* **Live dashboard** — Terminal-based real-time monitoring dashboard
* **JSON + SQLite logging** — Structured logs for easy analysis and integration with SIEM tools
* **Configurable banners** — Mimic real services to increase deception authenticity
* **Rate limiting** — Built-in connection throttling to handle aggressive scanners
* **Docker support** — One-command deployment
* **Plugin architecture** — Easily add custom service emulators
* **Alerting** — Webhook support for Slack/Discord/Telegram notifications

## Architecture

```
┌──────────────────────────────────────────────────┐
│                  ShadowTrap Core                  │
│  ┌──────────┐ ┌──────────┐ ┌──────────────────┐  │
│  │  Logger   │ │ GeoIP    │ │  Alert Manager   │  │
│  └────┬─────┘ └────┬─────┘ └────────┬─────────┘  │
│       │             │                │             │
│  ┌────▼─────────────▼────────────────▼──────────┐ │
│  │              Event Bus                        │ │
│  └──┬──────┬──────┬──────┬──────┬───────────────┘ │
│     │      │      │      │      │                  │
│  ┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐┌──▼──┐              │
│  │ SSH ││HTTP ││ FTP ││SMTP ││ Tel ││              │
│  └─────┘└─────┘└─────┘└─────┘└─────┘              │
└──────────────────────────────────────────────────┘
```

## Quick Start

### Prerequisites

* Python 3.9+
* pip

### Installation

```bash
git clone https://github.com/daecayde/shadowtrap.git
cd shadowtrap
pip install -r requirements.txt
```

### Configuration

Copy the example config and customize:

```bash
cp config/shadowtrap.example.yml config/shadowtrap.yml
```

Edit `config/shadowtrap.yml` to enable/disable services and set ports.

### Run

```bash
python -m shadowtrap --config config/shadowtrap.yml
```

Or run individual services:

```bash
python -m shadowtrap --service ssh --port 2222
python -m shadowtrap --service http --port 8080
```

### Docker

```bash
docker build -t shadowtrap .
docker run -d --name shadowtrap \\
  -p 2222:2222 -p 8080:8080 -p 2121:2121 \\
  -v $(pwd)/logs:/app/logs \\
  -v $(pwd)/config:/app/config \\
  shadowtrap
```

## Dashboard

Launch the live terminal dashboard:

```bash
python -m shadowtrap.dashboard
```

Shows real-time connection attempts, top attacker IPs, credential frequency, and geographic distribution.

## Log Format

All events are logged as structured JSON:

```json
{
  "timestamp": "2026-05-19T14:32:11.443Z",
  "service": "ssh",
  "src\_ip": "192.168.1.105",
  "src\_port": 48291,
  "dst\_port": 2222,
  "event\_type": "login\_attempt",
  "username": "root",
  "password": "admin123",
  "session\_id": "a3f8c2d1-9e4b-4f7a-b5c6-1d2e3f4a5b6c",
  "geo": {
    "country": "CN",
    "city": "Beijing",
    "lat": 39.9042,
    "lon": 116.4074
  },
  "raw\_input": null
}
```

## Project Structure

```
shadowtrap/
├── shadowtrap/
│   ├── \_\_init\_\_.py
│   ├── \_\_main\_\_.py          # CLI entry point
│   ├── core/
│   │   ├── \_\_init\_\_.py
│   │   ├── engine.py        # Main orchestrator
│   │   ├── logger.py        # Structured logging
│   │   ├── geoip.py         # IP geolocation
│   │   └── alerter.py       # Webhook notifications
│   ├── services/
│   │   ├── \_\_init\_\_.py
│   │   ├── base.py          # Base service class
│   │   ├── ssh\_trap.py      # SSH honeypot
│   │   ├── http\_trap.py     # HTTP honeypot
│   │   ├── ftp\_trap.py      # FTP honeypot
│   │   ├── smtp\_trap.py     # SMTP honeypot
│   │   └── telnet\_trap.py   # Telnet honeypot
│   └── dashboard/
│       ├── \_\_init\_\_.py
│       └── monitor.py       # Live TUI dashboard
├── config/
│   └── shadowtrap.example.yml
├── logs/
│   └── .gitkeep
├── tests/
│   ├── \_\_init\_\_.py
│   ├── test\_ssh.py
│   └── test\_logger.py
├── docs/
│   └── DEPLOYMENT.md
├── Dockerfile
├── docker-compose.yml
├── requirements.txt
├── setup.py
├── LICENSE
├── CONTRIBUTING.md
├── .gitignore
└── README.md
```

## Supported Services

|Service|Default Port|Emulates|Key Captures|
|-|-|-|-|
|SSH|2222|OpenSSH 8.9|Credentials, commands, key exchanges|
|HTTP|8080|Apache 2.4|URLs, headers, payloads, user-agents|
|FTP|2121|vsftpd 3.0|Credentials, file operations|
|SMTP|2525|Postfix|Sender/recipient, email content|
|Telnet|2323|BusyBox|Credentials, commands|

## Integrations

ShadowTrap logs can be forwarded to:

* **ELK Stack** (Elasticsearch, Logstash, Kibana)
* **Splunk** via JSON ingestion
* **Grafana** with SQLite/JSON datasource
* **MISP** for threat intelligence sharing

## Security Considerations

> ⚠️ \*\*Run honeypots in isolated environments.\*\* Never deploy on production networks without proper segmentation.

* Use dedicated VMs or containers
* Firewall rules should prevent lateral movement
* Monitor the honeypot host itself for compromise
* Rotate logs regularly and store securely

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

## License

This project is licensed under the MIT License — see [LICENSE](LICENSE) for details.

## Acknowledgments

* Inspired by [Cowrie](https://github.com/cowrie/cowrie), [Dionaea](https://github.com/DinoTools/dionaea), and [HoneyPy](https://github.com/foospidy/HoneyPy)
* GeoIP data powered by [MaxMind GeoLite2](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data)

\---

**Disclaimer:** This tool is intended for authorized security research and defensive purposes only. Unauthorized use of honeypots to entrap individuals or collect data without consent may violate local laws. Always ensure you have proper authorization before deployment.

