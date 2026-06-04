"""Abuse.ch feed clients — all using public bulk download endpoints, no key required."""
import httpx
import csv
import io


class AbusechClient:
    # All public bulk download endpoints — no authentication required
    URLHAUS_JSON    = "https://urlhaus.abuse.ch/downloads/json_recent/"
    THREATFOX_CSV   = "https://threatfox.abuse.ch/export/csv/recent/"
    MALWAREBAZAAR_TXT  = "https://bazaar.abuse.ch/export/txt/sha256/recent/"
    FEODO           = "https://feodotracker.abuse.ch/downloads/ipblocklist.json"

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
        """Uses the public CSV export — no API key required."""
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(self.THREATFOX_CSV)
            resp.raise_for_status()
            # ThreatFox header is a comment line — strip comments and hardcode fieldnames
            # Format: first_seen_utc,ioc_id,ioc_value,ioc_type,malware,malware_alias,
            #         malware_printable,last_seen_utc,confidence_level,reference,tags,anonymous,reporter
            TF_FIELDS = ["first_seen_utc","ioc_id","ioc_value","ioc_type","malware",
                         "malware_alias","malware_printable","last_seen_utc",
                         "confidence_level","reference","tags","anonymous","reporter"]
            data_lines = [l for l in resp.text.splitlines()
                          if l and not l.startswith("#") and not l.startswith("first_seen")]
            reader = csv.DictReader(data_lines, fieldnames=TF_FIELDS)
            items = []
            for row in reader:
                # ThreatFox CSV columns: first_seen_utc, ioc_id, ioc_value, ioc_type, ...
                ioc_value = (row.get("ioc_value") or row.get("ioc") or "").strip().strip('"')
                raw_type = (row.get("ioc_type") or "domain").strip().strip('"').lower()
                if not ioc_value:
                    continue
                if "ip" in raw_type:
                    ioc_type = "ip"
                elif "domain" in raw_type:
                    ioc_type = "domain"
                elif "url" in raw_type:
                    ioc_type = "url"
                elif "md5" in raw_type:
                    ioc_type = "md5"
                elif "sha256" in raw_type:
                    ioc_type = "sha256"
                else:
                    ioc_type = "domain"
                raw_tags = (row.get("tags") or "").strip().strip('"')
                tags = [t.strip() for t in raw_tags.split(",") if t.strip()] if raw_tags else []
                items.append({
                    "source": "threatfox",
                    "ioc_value": ioc_value[:512],
                    "ioc_type": ioc_type,
                    "tags": tags,
                    "metadata": {
                        "malware": (row.get("malware_printable") or row.get("malware") or "").strip()[:128],
                        "confidence": (row.get("confidence_level") or row.get("confidence") or "").strip()[:32],
                    },
                })
            return items[:300]

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
        """Uses the public SHA-256 text export — no API key required."""
        async with httpx.AsyncClient(timeout=20) as client:
            resp = await client.get(self.MALWAREBAZAAR_TXT)
            resp.raise_for_status()
            items = []
            for line in resp.text.splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                # Each line is a bare SHA-256 hash
                if len(line) == 64 and all(c in "0123456789abcdefABCDEF" for c in line):
                    items.append({
                        "source": "malwarebazaar",
                        "ioc_value": line.lower(),
                        "ioc_type": "sha256",
                        "tags": ["malware"],
                        "metadata": {},
                    })
            return items[:200]
