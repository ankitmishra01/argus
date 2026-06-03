"""GreyNoise community API — free tier, 1k requests/day."""
import httpx


class GreyNoiseClient:
    BASE = "https://api.greynoise.io/v3"
    COMMUNITY = "https://api.greynoise.io/v3/community"

    def __init__(self, api_key: str = ""):
        self.api_key = api_key
        self.headers = {"key": api_key} if api_key else {}

    async def lookup_ip(self, ip: str) -> dict:
        """Community endpoint — works without key but limited."""
        url = f"{self.COMMUNITY}/{ip}"
        async with httpx.AsyncClient(timeout=10) as client:
            resp = await client.get(url, headers=self.headers)
            if resp.status_code == 404:
                return {"source": "greynoise", "noise": False, "riot": False, "not_found": True}
            if resp.status_code != 200:
                return {}
            d = resp.json()
            return {
                "source": "greynoise",
                "noise": d.get("noise", False),
                "riot": d.get("riot", False),
                "classification": d.get("classification"),
                "name": d.get("name"),
                "link": d.get("link"),
                "last_seen": d.get("last_seen"),
                "message": d.get("message"),
            }

    async def fetch_noise_feed(self) -> list[dict]:
        """Requires paid key; returns empty list if no key."""
        if not self.api_key:
            return []
        async with httpx.AsyncClient(timeout=15) as client:
            resp = await client.get(
                f"{self.BASE}/noise/feed",
                headers=self.headers,
                params={"days": 1, "limit": 200},
            )
            if resp.status_code != 200:
                return []
            items = []
            for entry in resp.json().get("noise", []):
                items.append({
                    "source": "greynoise",
                    "ioc_value": entry.get("ip", ""),
                    "ioc_type": "ip",
                    "tags": entry.get("tags", []),
                    "metadata": {
                        "classification": entry.get("classification"),
                        "name": entry.get("name"),
                        "last_seen": entry.get("last_seen"),
                    },
                })
            return items
