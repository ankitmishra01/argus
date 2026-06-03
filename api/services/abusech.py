"""Abuse.ch feed clients — URLhaus, MalwareBazaar, ThreatFox, Feodo. All free, no key."""
import httpx


class AbusechClient:
    # URLhaus JSON download (no auth required)
    URLHAUS_JSON = "https://urlhaus.abuse.ch/downloads/json_recent/"
    MALWARE_BAZAAR = "https://mb-api.abuse.ch/api/v1/"
    THREATFOX = "https://threatfox-api.abuse.ch/api/v1/"
    FEODO = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

    async def fetch_urlhaus_recent(self) -> list[dict]:
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(self.URLHAUS_JSON)
            resp.raise_for_status()
            entries = resp.json()
            items = []
            for entry in (entries if isinstance(entries, list) else []):
                url = entry.get("url", "")
                if not url:
                    continue
                tags = []
                if entry.get("tags"):
                    tags = [t for t in entry["tags"] if t] if isinstance(entry["tags"], list) else []
                items.append({
                    "source": "urlhaus",
                    "ioc_value": url,
                    "ioc_type": "url",
                    "tags": tags,
                    "metadata": {
                        "url_status": entry.get("url_status"),
                        "threat": entry.get("threat"),
                        "host": entry.get("host"),
                    },
                })
            return items[:200]

    async def fetch_threatfox_recent(self) -> list[dict]:
        payload = {"query": "get_iocs", "days": 1}
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.post(self.THREATFOX, json=payload)
            resp.raise_for_status()
            data = resp.json()
            items = []
            for ioc in data.get("data", []) or []:
                ioc_type = (ioc.get("ioc_type") or "domain").lower()
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
            for entry in (data if isinstance(data, list) else []):
                ip = entry.get("ip_address", "")
                if not ip:
                    continue
                items.append({
                    "source": "feodo",
                    "ioc_value": ip,
                    "ioc_type": "ip",
                    "tags": ["c2", "botnet", (entry.get("malware") or "").lower()],
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
            for sample in data.get("data", []) or []:
                h = sample.get("sha256_hash", "")
                if not h:
                    continue
                items.append({
                    "source": "malwarebazaar",
                    "ioc_value": h,
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
