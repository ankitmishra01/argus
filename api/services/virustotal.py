"""VirusTotal free tier — 1,000 requests/day."""
import httpx
import base64


class VirusTotalClient:
    BASE = "https://www.virustotal.com/api/v3"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.headers = {"x-apikey": api_key} if api_key else {}

    def _risk_from_stats(self, stats: dict) -> int:
        malicious = stats.get("malicious", 0)
        suspicious = stats.get("suspicious", 0)
        total = sum(stats.values()) or 1
        score = ((malicious * 2 + suspicious) / (total * 2)) * 100
        return min(100, int(score))

    async def lookup_ip(self, ip: str) -> dict:
        if not self.api_key:
            return {}
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{self.BASE}/ip_addresses/{ip}", headers=self.headers)
            if resp.status_code != 200:
                return {}
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "source": "virustotal",
                "malicious": stats.get("malicious", 0),
                "harmless": stats.get("harmless", 0),
                "undetected": stats.get("undetected", 0),
                "risk_score": self._risk_from_stats(stats),
                "country": attrs.get("country"),
                "asn": attrs.get("asn"),
                "as_owner": attrs.get("as_owner"),
                "reputation": attrs.get("reputation", 0),
                "tags": attrs.get("tags", []),
            }

    async def lookup_domain(self, domain: str) -> dict:
        if not self.api_key:
            return {}
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{self.BASE}/domains/{domain}", headers=self.headers)
            if resp.status_code != 200:
                return {}
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "source": "virustotal",
                "malicious": stats.get("malicious", 0),
                "risk_score": self._risk_from_stats(stats),
                "categories": attrs.get("categories", {}),
                "reputation": attrs.get("reputation", 0),
                "tags": attrs.get("tags", []),
            }

    async def lookup_hash(self, hash_value: str) -> dict:
        if not self.api_key:
            return {}
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{self.BASE}/files/{hash_value}", headers=self.headers)
            if resp.status_code != 200:
                return {}
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "source": "virustotal",
                "malicious": stats.get("malicious", 0),
                "risk_score": self._risk_from_stats(stats),
                "type_description": attrs.get("type_description"),
                "size": attrs.get("size"),
                "names": (attrs.get("names") or [])[:3],
                "tags": attrs.get("tags", []),
            }

    async def lookup_url(self, url: str) -> dict:
        if not self.api_key:
            return {}
        url_id = base64.urlsafe_b64encode(url.encode()).decode().rstrip("=")
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(f"{self.BASE}/urls/{url_id}", headers=self.headers)
            if resp.status_code != 200:
                return {}
            attrs = resp.json().get("data", {}).get("attributes", {})
            stats = attrs.get("last_analysis_stats", {})
            return {
                "source": "virustotal",
                "malicious": stats.get("malicious", 0),
                "risk_score": self._risk_from_stats(stats),
                "final_url": attrs.get("last_final_url"),
                "title": attrs.get("title"),
                "tags": attrs.get("tags", []),
            }
