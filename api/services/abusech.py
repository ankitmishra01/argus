"""Abuse.ch feed clients — URLhaus, MalwareBazaar, ThreatFox, Feodo. All free, no key."""
import httpx
from datetime import datetime


class AbusechClient:
    URLHAUS = "https://urlhaus-api.abuse.ch/v1/urls/recent/limit/100/"
    MALWARE_BAZAAR = "https://mb-api.abuse.ch/api/v1/"
    THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
    FEODO = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

    async def fetch_urlhaus_recent(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(self.URLHAUS, data={"query": "get_urls", "limit": 100})
            resp.raise_for_status()
            data = resp.json()
            items = []
            for url_entry in data.get("urls", []):
                items.append({
                    "source": "urlhaus",
                    "ioc_value": url_entry.get("url", ""),
                    "ioc_type": "url",
                    "tags": [t.get("tag", "") for t in url_entry.get("tags", []) if t.get("tag")],
                    "metadata": {
                        "url_status": url_entry.get("url_status"),
                        "threat": url_entry.get("threat"),
                        "host": url_entry.get("host"),
                    },
                })
            return items

    async def fetch_threatfox_recent(self) -> list[dict]:
        payload = {"query": "get_iocs", "days": 1}
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(self.THREATFOX, json=payload)
            resp.raise_for_status()
            data = resp.json()
            items = []
            for ioc in data.get("data", []):
                ioc_type = ioc.get("ioc_type", "domain").lower()
                if "ip" in ioc_type:
                    ioc_type = "ip"
                elif "domain" in ioc_type:
                    ioc_type = "domain"
                elif "url" in ioc_type:
                    ioc_type = "url"
                elif "md5" in ioc_type:
                    ioc_type = "md5"
                elif "sha256" in ioc_type:
                    ioc_type = "sha256"
                items.append({
                    "source": "threatfox",
                    "ioc_value": ioc.get("ioc", ""),
                    "ioc_type": ioc_type,
                    "tags": ioc.get("tags") or [],
                    "metadata": {
                        "malware": ioc.get("malware"),
                        "confidence": ioc.get("confidence_level"),
                        "threat_type": ioc.get("threat_type"),
                    },
                })
            return items

    async def fetch_feodo_c2(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(self.FEODO)
            resp.raise_for_status()
            data = resp.json()
            items = []
            for entry in data:
                items.append({
                    "source": "feodo",
                    "ioc_value": entry.get("ip_address", ""),
                    "ioc_type": "ip",
                    "tags": ["c2", "botnet", entry.get("malware", "").lower()],
                    "metadata": {
                        "malware": entry.get("malware"),
                        "port": entry.get("port"),
                        "country": entry.get("country"),
                        "status": entry.get("status"),
                    },
                })
            return items

    async def fetch_malwarebazaar_recent(self) -> list[dict]:
        payload = {"query": "get_recent", "selector": "100"}
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(self.MALWARE_BAZAAR, data=payload)
            resp.raise_for_status()
            data = resp.json()
            items = []
            for sample in data.get("data", []):
                items.append({
                    "source": "malwarebazaar",
                    "ioc_value": sample.get("sha256_hash", ""),
                    "ioc_type": "sha256",
                    "tags": sample.get("tags") or [],
                    "metadata": {
                        "file_name": sample.get("file_name"),
                        "file_type": sample.get("file_type"),
                        "signature": sample.get("signature"),
                        "md5": sample.get("md5_hash"),
                    },
                })
            return items
