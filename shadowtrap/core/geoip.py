"""GeoIP resolution for attacker IP enrichment."""

from typing import Optional


class GeoIPResolver:
    """Resolve IP addresses to geographic locations using MaxMind GeoLite2."""

    def __init__(self, db_path: Optional[str] = None):
        self.reader = None
        if db_path:
            try:
                import geoip2.database
                self.reader = geoip2.database.Reader(db_path)
            except Exception:
                pass  # GeoIP is optional

    def lookup(self, ip: str) -> dict:
        """Look up geographic information for an IP address.

        Returns:
            Dict with country, city, lat, lon keys
        """
        if not self.reader or ip.startswith(("10.", "172.", "192.168.", "127.")):
            return {"country": "PRIVATE", "city": "N/A", "lat": 0.0, "lon": 0.0}

        try:
            response = self.reader.city(ip)
            return {
                "country": response.country.iso_code or "Unknown",
                "city": response.city.name or "Unknown",
                "lat": response.location.latitude or 0.0,
                "lon": response.location.longitude or 0.0,
            }
        except Exception:
            return {"country": "Unknown", "city": "Unknown", "lat": 0.0, "lon": 0.0}

    def close(self):
        if self.reader:
            self.reader.close()
