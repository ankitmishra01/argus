"""Threat intel routes — live feed, IOC lookup."""
import asyncio
from datetime import datetime, timedelta
from fastapi import APIRouter, Depends, Query
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from ..models import FeedItem, FeedStatus, get_db, get_settings
from ..services import OTXClient, GreyNoiseClient, VirusTotalClient
from ..services.abusech import AbusechClient

router = APIRouter(prefix="/intel", tags=["intel"])


class FeedItemOut(BaseModel):
    id: int
    source: str
    ioc_value: str
    ioc_type: str
    tags: list[str]
    metadata: dict
    seen_at: datetime

    class Config:
        from_attributes = True


class FeedStatusOut(BaseModel):
    source: str
    last_sync: datetime | None
    record_count: int
    status: str
    error: str | None

    class Config:
        from_attributes = True


@router.get("/feed", response_model=list[FeedItemOut])
async def get_feed(
    limit: int = Query(50, le=200),
    source: str | None = None,
    ioc_type: str | None = None,
    db: AsyncSession = Depends(get_db),
):
    q = select(FeedItem).order_by(desc(FeedItem.seen_at)).limit(limit)
    if source:
        q = q.where(FeedItem.source == source)
    if ioc_type:
        q = q.where(FeedItem.ioc_type == ioc_type)
    result = await db.execute(q)
    items = result.scalars().all()
    return [FeedItemOut(
        id=i.id, source=i.source, ioc_value=i.ioc_value,
        ioc_type=i.ioc_type, tags=i.tags or [],
        metadata=i.metadata_ or {}, seen_at=i.seen_at,
    ) for i in items]


@router.get("/feed/stats")
async def get_feed_stats(db: AsyncSession = Depends(get_db)):
    since_24h = datetime.utcnow() - timedelta(hours=24)
    result = await db.execute(
        select(FeedItem.source, func.count(FeedItem.id).label("count"))
        .where(FeedItem.seen_at >= since_24h)
        .group_by(FeedItem.source)
    )
    rows = result.all()
    total = await db.execute(select(func.count(FeedItem.id)))
    return {
        "by_source_24h": {r.source: r.count for r in rows},
        "total": total.scalar() or 0,
    }


@router.get("/sources", response_model=list[FeedStatusOut])
async def get_sources(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(FeedStatus))
    return result.scalars().all()


@router.get("/lookup/{ioc}")
async def lookup_ioc(ioc: str):
    """Enrich a single IOC against all configured sources in parallel."""
    settings = get_settings()
    ioc = ioc.strip()

    # Detect IOC type
    import re
    ip_pattern = re.compile(r"^\d{1,3}(\.\d{1,3}){3}$")
    hash_md5 = re.compile(r"^[a-fA-F0-9]{32}$")
    hash_sha256 = re.compile(r"^[a-fA-F0-9]{64}$")
    url_pattern = re.compile(r"^https?://")

    if ip_pattern.match(ioc):
        ioc_type = "ip"
    elif hash_sha256.match(ioc):
        ioc_type = "sha256"
    elif hash_md5.match(ioc):
        ioc_type = "md5"
    elif url_pattern.match(ioc):
        ioc_type = "url"
    else:
        ioc_type = "domain"

    otx = OTXClient(settings.otx_api_key)
    gn = GreyNoiseClient(settings.greynoise_api_key)
    vt = VirusTotalClient(settings.vt_api_key)

    sources = {}

    async def safe(name, coro):
        try:
            sources[name] = await coro
        except Exception as e:
            sources[name] = {"error": str(e)}

    if ioc_type == "ip":
        await asyncio.gather(
            safe("otx", otx.lookup_ip(ioc)),
            safe("greynoise", gn.lookup_ip(ioc)),
            safe("virustotal", vt.lookup_ip(ioc)),
        )
    elif ioc_type == "domain":
        await asyncio.gather(
            safe("otx", otx.lookup_domain(ioc)),
            safe("virustotal", vt.lookup_domain(ioc)),
        )
    elif ioc_type in ("sha256", "md5"):
        await asyncio.gather(
            safe("otx", otx.lookup_hash(ioc)),
            safe("virustotal", vt.lookup_hash(ioc)),
        )
    elif ioc_type == "url":
        await asyncio.gather(
            safe("virustotal", vt.lookup_url(ioc)),
        )

    # Compute aggregate risk score
    scores = [s.get("risk_score", 0) for s in sources.values() if isinstance(s, dict) and "risk_score" in s]
    agg_score = max(scores) if scores else 0

    # Aggregate tags
    all_tags = list({
        t for s in sources.values() if isinstance(s, dict)
        for t in s.get("tags", []) if t
    })

    return {
        "ioc": ioc,
        "ioc_type": ioc_type,
        "risk_score": agg_score,
        "tags": all_tags[:20],
        "sources": sources,
    }
