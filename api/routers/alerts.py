"""Alert CRUD routes."""
from datetime import datetime
from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import select, desc, func
from sqlalchemy.ext.asyncio import AsyncSession
from pydantic import BaseModel
from ..models import Alert, AlertStatus, Severity, get_db

router = APIRouter(prefix="/alerts", tags=["alerts"])


class AlertCreate(BaseModel):
    title: str
    description: str | None = None
    severity: Severity = Severity.MEDIUM
    source: str = "manual"
    ioc_value: str | None = None
    tags: list[str] = []
    assignee: str | None = None


class NoteAdd(BaseModel):
    text: str
    author: str = "analyst"


class AlertOut(BaseModel):
    id: int
    title: str
    description: str | None
    severity: str
    status: str
    source: str
    ioc_value: str | None
    tags: list[str]
    assignee: str | None
    notes: list[dict]
    incident_id: int | None
    created_at: datetime
    updated_at: datetime

    class Config:
        from_attributes = True


@router.get("/", response_model=list[AlertOut])
async def list_alerts(
    status: str | None = None,
    severity: str | None = None,
    limit: int = Query(50, le=200),
    db: AsyncSession = Depends(get_db),
):
    q = select(Alert).order_by(desc(Alert.created_at)).limit(limit)
    if status:
        q = q.where(Alert.status == status)
    if severity:
        q = q.where(Alert.severity == severity)
    result = await db.execute(q)
    return result.scalars().all()


@router.get("/stats")
async def alert_stats(db: AsyncSession = Depends(get_db)):
    result = await db.execute(
        select(Alert.severity, Alert.status, func.count(Alert.id).label("count"))
        .group_by(Alert.severity, Alert.status)
    )
    rows = result.all()
    by_severity = {}
    by_status = {}
    for r in rows:
        by_severity[r.severity] = by_severity.get(r.severity, 0) + r.count
        by_status[r.status] = by_status.get(r.status, 0) + r.count
    return {"by_severity": by_severity, "by_status": by_status}


@router.post("/", response_model=AlertOut, status_code=201)
async def create_alert(body: AlertCreate, db: AsyncSession = Depends(get_db)):
    alert = Alert(**body.model_dump())
    db.add(alert)
    await db.commit()
    await db.refresh(alert)
    return alert


@router.get("/{alert_id}", response_model=AlertOut)
async def get_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alert not found")
    return alert


@router.patch("/{alert_id}/status", response_model=AlertOut)
async def update_status(alert_id: int, status: AlertStatus, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alert not found")
    alert.status = status
    await db.commit()
    await db.refresh(alert)
    return alert


@router.post("/{alert_id}/notes", response_model=AlertOut)
async def add_note(alert_id: int, body: NoteAdd, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alert not found")
    notes = list(alert.notes or [])
    notes.append({"text": body.text, "author": body.author, "ts": datetime.utcnow().isoformat()})
    alert.notes = notes
    await db.commit()
    await db.refresh(alert)
    return alert


@router.delete("/{alert_id}", status_code=204)
async def delete_alert(alert_id: int, db: AsyncSession = Depends(get_db)):
    result = await db.execute(select(Alert).where(Alert.id == alert_id))
    alert = result.scalar_one_or_none()
    if not alert:
        raise HTTPException(404, "Alert not found")
    await db.delete(alert)
    await db.commit()
