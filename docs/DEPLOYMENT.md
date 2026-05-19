# Deployment Guide

## Production Deployment

### Prerequisites
- Linux server (Ubuntu 22.04+ recommended)
- Python 3.9+ or Docker
- Root access or sudo privileges (for ports < 1024)
- GeoLite2 City database (optional, for GeoIP enrichment)

### Option 1: Direct Deployment

```bash
# Clone and install
git clone https://github.com/yourusername/shadowtrap.git
cd shadowtrap
python -m venv venv
source venv/bin/activate
pip install -r requirements.txt

# Configure
cp config/shadowtrap.example.yml config/shadowtrap.yml
nano config/shadowtrap.yml

# Run with systemd (recommended)
sudo cp docs/shadowtrap.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable shadowtrap
sudo systemctl start shadowtrap
```

### Option 2: Docker Deployment

```bash
docker-compose up -d
docker-compose logs -f
```

### Network Isolation

**Critical:** Always run honeypots in isolated network segments.

```bash
# Example iptables rules for the honeypot host
iptables -A INPUT -p tcp --dport 2222 -j ACCEPT
iptables -A INPUT -p tcp --dport 8080 -j ACCEPT
iptables -A INPUT -p tcp --dport 2121 -j ACCEPT
iptables -A OUTPUT -d 10.0.0.0/8 -j DROP     # Block internal network access
iptables -A OUTPUT -d 172.16.0.0/12 -j DROP
iptables -A OUTPUT -d 192.168.0.0/16 -j DROP
```

### Port Forwarding

To make honeypots appear on standard ports, use iptables NAT:

```bash
iptables -t nat -A PREROUTING -p tcp --dport 22 -j REDIRECT --to-port 2222
iptables -t nat -A PREROUTING -p tcp --dport 80 -j REDIRECT --to-port 8080
iptables -t nat -A PREROUTING -p tcp --dport 21 -j REDIRECT --to-port 2121
```

### GeoIP Setup

1. Sign up at [MaxMind](https://www.maxmind.com/en/geolite2/signup)
2. Download GeoLite2-City.mmdb
3. Place it at `/usr/share/GeoIP/GeoLite2-City.mmdb`
4. Set the path in your config file

### Log Rotation

Add to `/etc/logrotate.d/shadowtrap`:

```
/path/to/shadowtrap/logs/*.json {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    copytruncate
}
```

### Monitoring

Use the built-in dashboard:
```bash
python -m shadowtrap.dashboard
```

Or forward logs to your SIEM:
- **ELK Stack:** Configure Filebeat to read `logs/events.json`
- **Splunk:** Use the JSON file monitor input
- **Grafana:** Use SQLite datasource plugin with `logs/shadowtrap.db`

### Security Hardening

1. Run as a non-root user with only NET_BIND_SERVICE capability
2. Use read-only filesystem where possible
3. Drop all unnecessary capabilities
4. Enable AppArmor or SELinux profiles
5. Monitor the honeypot host for signs of compromise
6. Use separate logging infrastructure
