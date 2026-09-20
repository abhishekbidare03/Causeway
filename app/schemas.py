"""Pydantic request/response models for the API."""

from datetime import datetime
from typing import List, Optional

from pydantic import BaseModel, Field


class LogIn(BaseModel):
    """A single normalized log event submitted to POST /logs."""

    timestamp: Optional[datetime] = Field(
        default=None,
        description="Event time (ISO 8601). Defaults to server time if omitted.",
    )
    ip: str = Field(..., min_length=3, max_length=45)
    user: Optional[str] = Field(default=None, max_length=64)
    endpoint: str = Field(..., min_length=1, max_length=255)
    status: int = Field(..., ge=100, le=599, description="HTTP status code")
    bytes: int = Field(default=0, ge=0)
    layer: str = Field(default="app", max_length=16)


class LogAccepted(BaseModel):
    ok: bool = True
    id: int


class EventOut(BaseModel):
    id: int
    ts: datetime
    ip: str
    endpoint: Optional[str]
    rule_flag: bool
    rule_type: str
    ml_score: float
    ml_flag: bool
    req_count: int
    fail_rate: float
    incident_id: Optional[int]

    class Config:
        from_attributes = True


class IncidentOut(BaseModel):
    id: int
    start_ts: datetime
    end_ts: datetime
    patient_zero: str
    blast_radius: int
    kill_chain: List[str]
    
    events: List[EventOut] = []

    class Config:
        from_attributes = True


class TopIP(BaseModel):
    ip: str
    count: int


class RpsPoint(BaseModel):
    t: str
    count: int


class StatsOut(BaseModel):
    rps: List[RpsPoint]
    current_rps: float
    top_ips: List[TopIP]
    active_attacks: int
    ml_watch: int
    total_logs: int
    total_events: int
    ml_trained: bool
