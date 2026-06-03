"""Incident lifecycle routes (PICERL)."""
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select, desc
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from ..models import Incident, IncidentStatus, Severity, get_db

router = APIRouter(prefix="/incidents", tags=["incidents"])


class IncidentCreate(BaseModel):
    title: str
    summary: str | None = None
    severity: Severity = Severity.MEDIUM
    affected_assets: list[str] = []


class IncidentUpdate(BaseModel):
    title: str | None = None
    summary: str | None = None
    severity: Severity | None = None
    status: IncidentStatus | None = None
    notes: str | None = None
    affected_assets: list[str] | None = None
    evidence: list[dict] | None = None
    actions_taken: list[dict] | None = None


class TimelineEntry(BaseModel):
    text: str
    author: str = "analyst"


class IncidentOut(BaseModel):
    id: int
    title: str
    summary: str | None
    severity: str
    status: str
    affected_assets: list[str]
    timeline: list[dict]
    notes: str | None
    evidence: list[dict]
    actions_taken: list[dict]
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


@router.get("/", response_model=list[IncidentOut])
async def list_incidents(db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Incident).order_by(desc(Incident.created_at)))
    return result.scalars().all()


@router.post("/", response_model=IncidentOut, status_code=201)
async def create_incident(body: IncidentCreate, db: AsyncSession = Depends(get_db)):
    incident = Incident(**body.model_dump())
    incident.timeline = [{"text": "Incident created", "author": "system", "ts": datetime.utcnow().isoformat()}]
    db.add(incident)
    await db.commit()
    await db.refresh(incident)
    return incident


@router.get("/{incident_id}", response_model=IncidentOut)
async def get_incident(incident_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    inc = result.scalar_one_or_none()
    if not inc:
        raise HTTPException(404, "Incident not found")
    return inc


@router.patch("/{incident_id}", response_model=IncidentOut)
async def update_incident(incident_id: int, body: IncidentUpdate, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    inc = result.scalar_one_or_none()
    if not inc:
        raise HTTPException(404, "Incident not found")
    for field, val in body.model_dump(exclude_none=True).items():
        setattr(inc, field, val)
    await db.commit()
    await db.refresh(inc)
    return inc


@router.post("/{incident_id}/timeline", response_model=IncidentOut)
async def add_timeline(incident_id: int, body: TimelineEntry, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    inc = result.scalar_one_or_none()
    if not inc:
        raise HTTPException(404, "Incident not found")
    timeline = list(inc.timeline or [])
    timeline.append({"text": body.text, "author": body.author, "ts": datetime.utcnow().isoformat()})
    inc.timeline = timeline
    await db.commit()
    await db.refresh(inc)
    return inc


@router.get("/{incident_id}/report")
async def generate_report(incident_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Incident).where(Incident.id == incident_id))
    inc = result.scalar_one_or_none()
    if not inc:
        raise HTTPException(404, "Incident not found")

    lines = [
        f"# Incident Report: {inc.title}",
        f"",
        f"**ID:** INC-{inc.id:04d}  ",
        f"**Severity:** {inc.severity.upper()}  ",
        f"**Status:** {inc.status.replace('_', ' ').title()}  ",
        f"**Created:** {inc.created_at.strftime('%Y-%m-%d %H:%M UTC')}  ",
        f"**Updated:** {inc.updated_at.strftime('%Y-%m-%d %H:%M UTC')}",
        f"",
        f"## Summary",
        inc.summary or "_No summary provided._",
        f"",
        f"## Affected Assets",
    ]
    for asset in (inc.affected_assets or []):
        lines.append(f"- {asset}")
    if not inc.affected_assets:
        lines.append("_None recorded._")

    lines += ["", "## Timeline"]
    for entry in (inc.timeline or []):
        lines.append(f"- **{entry.get('ts', '')}** [{entry.get('author', '')}]: {entry.get('text', '')}")

    lines += ["", "## Evidence"]
    for ev in (inc.evidence or []):
        lines.append(f"- {ev}")

    lines += ["", "## Actions Taken"]
    for action in (inc.actions_taken or []):
        lines.append(f"- {action}")

    lines += ["", "## Analyst Notes", inc.notes or "_No notes._"]

    return {"report_md": "\n".join(lines), "incident_id": incident_id}
