"""Background feed sync jobs using APScheduler."""
import asyncio
import logging
from datetime import datetime, timezone
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from sqlalchemy import select, update, insert
from .models import FeedItem, FeedStatus, get_session_factory, get_settings
from .services import AbusechClient, OTXClient

logger = logging.getLogger(__name__)
scheduler = AsyncIOScheduler()


async def _upsert_feed_items(items: list[dict], source: str) -> int:
    factory = get_session_factory()
    count = 0
    async with factory() as session:
        for item in items:
            if not item.get("ioc_value"):
                continue
            existing = await session.execute(
                select(FeedItem).where(
                    FeedItem.source == source,
                    FeedItem.ioc_value == item["ioc_value"],
                )
            )
            if existing.scalar_one_or_none() is None:
                session.add(FeedItem(
                    source=source,
                    ioc_value=item["ioc_value"],
                    ioc_type=item.get("ioc_type", "unknown"),
                    tags=item.get("tags", []),
                    metadata_=item.get("metadata", {}),
                    seen_at=datetime.now(timezone.utc),
                ))
                count += 1
        await session.commit()

    await _update_feed_status(source, count)
    return count


async def _update_feed_status(source: str, new_count: int, error: str | None = None):
    factory = get_session_factory()
    async with factory() as session:
        existing = await session.execute(
            select(FeedStatus).where(FeedStatus.source == source)
        )
        status_row = existing.scalar_one_or_none()
        now = datetime.now(timezone.utc)

        if status_row:
            status_row.last_sync = now
            status_row.record_count = status_row.record_count + new_count
            status_row.status = "error" if error else "ok"
            status_row.error = error
        else:
            session.add(FeedStatus(
                source=source,
                last_sync=now,
                record_count=new_count,
                status="error" if error else "ok",
                error=error,
            ))
        await session.commit()


async def sync_abusech():
    client = AbusechClient()
    sources = [
        ("urlhaus", client.fetch_urlhaus_recent),
        ("threatfox", client.fetch_threatfox_recent),
        ("feodo", client.fetch_feodo_c2),
        ("malwarebazaar", client.fetch_malwarebazaar_recent),
    ]
    for source, fn in sources:
        try:
            items = await fn()
            count = await _upsert_feed_items(items, source)
            logger.info(f"[{source}] synced {count} new items")
        except Exception as e:
            logger.error(f"[{source}] sync failed: {e}")
            await _update_feed_status(source, 0, str(e))


async def sync_otx():
    settings = get_settings()
    if not settings.otx_api_key:
        return
    client = OTXClient(settings.otx_api_key)
    try:
        items = await client.get_recent_pulses()
        count = await _upsert_feed_items(items, "otx")
        logger.info(f"[otx] synced {count} new items")
    except Exception as e:
        logger.error(f"[otx] sync failed: {e}")
        await _update_feed_status("otx", 0, str(e))


def start_scheduler():
    scheduler.add_job(sync_abusech, "interval", minutes=15, id="abusech", replace_existing=True)
    scheduler.add_job(sync_otx, "interval", hours=1, id="otx", replace_existing=True)
    scheduler.start()
    # Run immediately on startup
    asyncio.get_event_loop().call_later(2, lambda: asyncio.ensure_future(sync_abusech()))
