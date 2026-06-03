"""AlienVault OTX client — free API, requires account."""
import httpx
from typing import Optional


class OTXClient:
    BASE = "https://otx.alienvault.com/api/v1"

    def __init__(self, api_key: str):
        self.api_key = api_key
        self.headers = {"X-OTX-API-KEY": api_key} if api_key else {}

    async def get_recent_pulses(self, limit: int = 20) -> list[dict]:
        if not self.api_key:
            return []
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{self.BASE}/pulses/subscribed",
                headers=self.headers,
                params={"limit": limit},
            )
            if resp.status_code != 200:
                return []
            data = resp.json()
            items = []
            for pulse in data.get("results", []):
                for indicator in pulse.get("indicators", [])[:20]:
                    itype = indicator.get("type", "").lower()
                    ioc_type = "domain"
                    if itype in ("ipv4", "ipv6"):
                        ioc_type = "ip"
                    elif itype == "url":
                        ioc_type = "url"
                    elif itype == "filehash-md5":
                        ioc_type = "md5"
                    elif itype in ("filehash-sha256", "sha256"):
                        ioc_type = "sha256"
                    items.append({
                        "source": "otx",
                        "ioc_value": indicator.get("indicator", ""),
                        "ioc_type": ioc_type,
                        "tags": pulse.get("tags", []),
                        "metadata": {
                            "pulse_name": pulse.get("name"),
                            "pulse_id": pulse.get("id"),
                            "author": pulse.get("author", {}).get("username"),
                            "description": indicator.get("description"),
                        },
                    })
            return items

    async def lookup_ip(self, ip: str) -> dict:
        if not self.api_key:
            return {}
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{self.BASE}/indicators/IPv4/{ip}/general",
                headers=self.headers,
            )
            if resp.status_code != 200:
                return {}
            d = resp.json()
            return {
                "source": "otx",
                "reputation": d.get("reputation", 0),
                "pulse_count": d.get("pulse_info", {}).get("count", 0),
                "country": d.get("country_name"),
                "asn": d.get("asn"),
                "tags": [t for p in d.get("pulse_info", {}).get("pulses", []) for t in p.get("tags", [])],
            }

    async def lookup_domain(self, domain: str) -> dict:
        if not self.api_key:
            return {}
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{self.BASE}/indicators/domain/{domain}/general",
                headers=self.headers,
            )
            if resp.status_code != 200:
                return {}
            d = resp.json()
            return {
                "source": "otx",
                "pulse_count": d.get("pulse_info", {}).get("count", 0),
                "tags": [t for p in d.get("pulse_info", {}).get("pulses", []) for t in p.get("tags", [])],
            }

    async def lookup_hash(self, hash_value: str) -> dict:
        if not self.api_key:
            return {}
        hash_type = "sha256" if len(hash_value) == 64 else "md5"
        endpoint = "FileHash-SHA256" if hash_type == "sha256" else "FileHash-MD5"
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(
                f"{self.BASE}/indicators/{endpoint}/{hash_value}/general",
                headers=self.headers,
            )
            if resp.status_code != 200:
                return {}
            d = resp.json()
            return {
                "source": "otx",
                "pulse_count": d.get("pulse_info", {}).get("count", 0),
                "malware_family": d.get("malware_families", []),
                "tags": [t for p in d.get("pulse_info", {}).get("pulses", []) for t in p.get("tags", [])],
            }
