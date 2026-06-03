"""ARGUS API — main FastAPI application."""
import logging
from contextlib import asynccontextmanager
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from sqlalchemy import text
from .models import Base, get_engine
from .routers import intel_router, alerts_router, incidents_router
from .scheduler import start_scheduler, scheduler

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("argus")


@asynccontextmanager
async def lifespan(app: FastAPI):
    # Create all tables
    engine = get_engine()
    async with engine.begin() as conn:
        await conn.run_sync(Base.metadata.create_all)
    logger.info("Database tables ready")

    # Start background feed sync
    start_scheduler()
    logger.info("Scheduler started")

    yield

    scheduler.shutdown(wait=False)
    await engine.dispose()


app = FastAPI(
    title="ARGUS Security Operations",
    description="Open-source SOC dashboard — threat intel, alerts, incidents",
    version="0.1.0",
    lifespan=lifespan,
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

app.include_router(intel_router)
app.include_router(alerts_router)
app.include_router(incidents_router)


@app.get("/health")
async def health():
    return {"status": "ok", "service": "argus"}
