"""
CRUD API endpoints for Cron triggers under /api/v2/schedules.
"""

from __future__ import annotations

import logging
import time
from typing import Any, Dict, List, Optional
import uuid
import zoneinfo

from croniter import croniter
from fastapi import APIRouter, HTTPException, Request
from pydantic import BaseModel, Field

from agentos.storage.models import ScheduleRecord, utcnow

logger = logging.getLogger(__name__)

router = APIRouter(prefix="/schedules", tags=["schedules"])


class CreateScheduleRequest(BaseModel):
    name: str = Field(..., min_length=1)
    flow_id: str = Field(..., min_length=1)
    cron_expression: str = Field(..., min_length=1)
    timezone: str = "UTC"
    inputs: Dict[str, Any] = Field(default_factory=dict)
    misfire_policy: str = "skip"  # "skip" | "fire_once"


class UpdateScheduleRequest(BaseModel):
    name: Optional[str] = None
    flow_id: Optional[str] = None
    cron_expression: Optional[str] = None
    timezone: Optional[str] = None
    inputs: Optional[Dict[str, Any]] = None
    misfire_policy: Optional[str] = None
    enabled: Optional[bool] = None


class ScheduleResponse(BaseModel):
    schedule_id: str
    name: str
    flow_id: str
    cron_expression: str
    timezone: str
    inputs: Dict[str, Any]
    misfire_policy: str
    enabled: bool
    last_run_at: Optional[Any] = None
    next_run_at: Optional[Any] = None
    created_at: Any
    updated_at: Any


def _validate_cron_and_tz(cron_expr: str, tz_name: str) -> None:
    try:
        zoneinfo.ZoneInfo(tz_name)
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid timezone {tz_name!r}: {e}") from e

    if not croniter.is_valid(cron_expr):
        raise HTTPException(status_code=400, detail=f"Invalid 5-field cron expression: {cron_expr!r}")


@router.post("", response_model=ScheduleResponse, status_code=201)
async def create_schedule(req: CreateScheduleRequest, request: Request) -> ScheduleResponse:
    storage = request.app.state.storage
    if not storage.schedules:
        raise HTTPException(status_code=500, detail="Schedule storage repository unavailable")

    _validate_cron_and_tz(req.cron_expression, req.timezone)

    if req.misfire_policy not in ("skip", "fire_once"):
        raise HTTPException(status_code=400, detail=f"Invalid misfire_policy {req.misfire_policy!r}; must be 'skip' or 'fire_once'")

    if storage.flows:
        flow = await storage.flows.get_draft(req.flow_id)
        if not flow:
            raise HTTPException(status_code=404, detail=f"Flow {req.flow_id!r} not found")

    schedule_id = f"sched_{uuid.uuid4().hex[:12]}"
    record = ScheduleRecord(
        schedule_id=schedule_id,
        name=req.name,
        flow_id=req.flow_id,
        cron_expression=req.cron_expression,
        timezone=req.timezone,
        inputs=req.inputs,
        misfire_policy=req.misfire_policy,
        enabled=True,
    )
    await storage.schedules.put(record)

    return ScheduleResponse(
        schedule_id=record.schedule_id,
        name=record.name,
        flow_id=record.flow_id,
        cron_expression=record.cron_expression,
        timezone=record.timezone,
        inputs=record.inputs,
        misfire_policy=record.misfire_policy,
        enabled=record.enabled,
        last_run_at=record.last_run_at,
        next_run_at=record.next_run_at,
        created_at=record.created_at,
        updated_at=record.updated_at,
    )


@router.get("", response_model=List[ScheduleResponse])
async def list_schedules(request: Request) -> List[ScheduleResponse]:
    storage = request.app.state.storage
    if not storage.schedules:
        return []
    scheds = await storage.schedules.list()
    return [
        ScheduleResponse(
            schedule_id=s.schedule_id,
            name=s.name,
            flow_id=s.flow_id,
            cron_expression=s.cron_expression,
            timezone=s.timezone,
            inputs=s.inputs,
            misfire_policy=s.misfire_policy,
            enabled=s.enabled,
            last_run_at=s.last_run_at,
            next_run_at=s.next_run_at,
            created_at=s.created_at,
            updated_at=s.updated_at,
        )
        for s in scheds
    ]


@router.get("/{schedule_id}", response_model=ScheduleResponse)
async def get_schedule(schedule_id: str, request: Request) -> ScheduleResponse:
    storage = request.app.state.storage
    if not storage.schedules:
        raise HTTPException(status_code=404, detail="Schedule not found")
    sched = await storage.schedules.get(schedule_id)
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")
    return ScheduleResponse(
        schedule_id=sched.schedule_id,
        name=sched.name,
        flow_id=sched.flow_id,
        cron_expression=sched.cron_expression,
        timezone=sched.timezone,
        inputs=sched.inputs,
        misfire_policy=sched.misfire_policy,
        enabled=sched.enabled,
        last_run_at=sched.last_run_at,
        next_run_at=sched.next_run_at,
        created_at=sched.created_at,
        updated_at=sched.updated_at,
    )


@router.put("/{schedule_id}", response_model=ScheduleResponse)
async def update_schedule(schedule_id: str, req: UpdateScheduleRequest, request: Request) -> ScheduleResponse:
    storage = request.app.state.storage
    if not storage.schedules:
        raise HTTPException(status_code=404, detail="Schedule not found")
    sched = await storage.schedules.get(schedule_id)
    if not sched:
        raise HTTPException(status_code=404, detail="Schedule not found")

    cron_to_check = req.cron_expression or sched.cron_expression
    tz_to_check = req.timezone or sched.timezone
    _validate_cron_and_tz(cron_to_check, tz_to_check)

    if req.name is not None:
        sched.name = req.name
    if req.flow_id is not None:
        sched.flow_id = req.flow_id
    if req.cron_expression is not None:
        sched.cron_expression = req.cron_expression
    if req.timezone is not None:
        sched.timezone = req.timezone
    if req.inputs is not None:
        sched.inputs = req.inputs
    if req.misfire_policy is not None:
        if req.misfire_policy not in ("skip", "fire_once"):
            raise HTTPException(status_code=400, detail=f"Invalid misfire_policy {req.misfire_policy!r}")
        sched.misfire_policy = req.misfire_policy
    if req.enabled is not None:
        sched.enabled = req.enabled
    sched.updated_at = utcnow()

    await storage.schedules.put(sched)
    return ScheduleResponse(
        schedule_id=sched.schedule_id,
        name=sched.name,
        flow_id=sched.flow_id,
        cron_expression=sched.cron_expression,
        timezone=sched.timezone,
        inputs=sched.inputs,
        misfire_policy=sched.misfire_policy,
        enabled=sched.enabled,
        last_run_at=sched.last_run_at,
        next_run_at=sched.next_run_at,
        created_at=sched.created_at,
        updated_at=sched.updated_at,
    )


@router.delete("/{schedule_id}", status_code=204)
async def delete_schedule(schedule_id: str, request: Request) -> None:
    storage = request.app.state.storage
    if not storage.schedules:
        raise HTTPException(status_code=404, detail="Schedule not found")
    deleted = await storage.schedules.delete(schedule_id)
    if not deleted:
        raise HTTPException(status_code=404, detail="Schedule not found")
