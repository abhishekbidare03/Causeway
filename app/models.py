"""SQLAlchemy ORM models: the three tables of the pipeline.

logs      -> raw normalized log events as ingested
features  -> per-IP statistical features computed over 5-second windows
events    -> detections, carrying BOTH the rule verdict and the ML score
"""

from datetime import datetime, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
)
from sqlalchemy.orm import declarative_base, relationship

Base = declarative_base()


def _utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


class Log(Base):
    """A single normalized log event from any layer."""

    __tablename__ = "logs"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime, nullable=False, index=True)
    ip = Column(String(45), nullable=False, index=True)
    user = Column(String(64), nullable=True)
    endpoint = Column(String(255), nullable=False)
    # HTTP status code. Anything >= 400 counts as a failed request.
    status = Column(Integer, nullable=False)
    bytes = Column(Integer, nullable=False, default=0)
    # network / app / system / iam
    layer = Column(String(16), nullable=False, default="app")
    received_at = Column(DateTime, nullable=False, default=_utcnow)

    # The feature engine scans one time window and groups by IP on every tick.
    __table_args__ = (Index("ix_logs_ts_ip", "ts", "ip"),)


class Feature(Base):
    """Statistical feature vector for one IP over one 5-second window."""

    __tablename__ = "features"

    id = Column(Integer, primary_key=True, autoincrement=True)
    window_start = Column(DateTime, nullable=False)
    window_end = Column(DateTime, nullable=False, index=True)
    ip = Column(String(45), nullable=False, index=True)

    req_count = Column(Integer, nullable=False)
    fail_rate = Column(Float, nullable=False)
    unique_endpoints = Column(Integer, nullable=False)
    avg_interarrival = Column(Float, nullable=False)
    bytes_sum = Column(Integer, nullable=False, default=0)

    # Most-targeted endpoint in the window, kept for display in the UI.
    top_endpoint = Column(String(255), nullable=True)
    created_at = Column(DateTime, nullable=False, default=_utcnow)


class Incident(Base):
    """An incident grouping related events together."""

    __tablename__ = "incidents"

    id = Column(Integer, primary_key=True, autoincrement=True)
    start_ts = Column(DateTime, nullable=False, index=True)
    end_ts = Column(DateTime, nullable=False)
    patient_zero = Column(String(45), nullable=False)
    blast_radius = Column(Integer, nullable=False, default=0)
    kill_chain = Column(Text, nullable=False, default="[]")  # JSON string list of stages

    # Relationship to events
    events = relationship("Event", back_populates="incident")


class Event(Base):
    """A detection.

    Written whenever the rule engine OR the ML model flags a feature vector.
    Both verdicts are always stored -- the hybrid detection story depends on
    showing them side by side rather than collapsing them into one answer.
    """

    __tablename__ = "events"

    id = Column(Integer, primary_key=True, autoincrement=True)
    ts = Column(DateTime, nullable=False, index=True)
    ip = Column(String(45), nullable=False, index=True)
    endpoint = Column(String(255), nullable=True)

    rule_flag = Column(Boolean, nullable=False, default=False)
    rule_type = Column(String(32), nullable=False, default="none")

    ml_score = Column(Float, nullable=False, default=0.0)
    ml_flag = Column(Boolean, nullable=False, default=False)

    # Denormalized snapshot of the feature vector for the dashboard table.
    req_count = Column(Integer, nullable=False, default=0)
    fail_rate = Column(Float, nullable=False, default=0.0)

    feature_id = Column(Integer, ForeignKey("features.id"), nullable=True)
    incident_id = Column(Integer, ForeignKey("incidents.id"), nullable=True, index=True)
    
    incident = relationship("Incident", back_populates="events")
    
    created_at = Column(DateTime, nullable=False, default=_utcnow)
