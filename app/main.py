"""FastAPI application: log ingestion, detection loop, and dashboard API.

Run with:  uvicorn app.main:app --reload
"""

import asyncio
import logging
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import List

from fastapi import Depends, FastAPI, Query
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles
from sqlalchemy import func
from sqlalchemy.orm import Session

from app.config import (
    ACTIVE_ATTACK_SECONDS,
    BRUTE_FAIL_RATE,
    BRUTE_MIN_REQ,
    DOS_REQ_COUNT,
    ML_MIN_REQ_COUNT,
    ML_SCORE_THRESHOLD,
    RETRAIN_INTERVAL,
    STATS_WINDOW_SECONDS,
    WINDOW_SECONDS,
)
from app.db import SessionLocal, get_session, init_db
from app.detection.ml_model import detector
from app.detection.rules import apply_rules, describe_rules
from app.features import compute_window, feature_vector
from app.models import Event, Log
from app.schemas import EventOut, LogAccepted, LogIn, RpsPoint, StatsOut, TopIP

logging.basicConfig(
    level=logging.INFO, format="%(asctime)s  %(levelname)-7s %(name)s: %(message)s"
)
log = logging.getLogger("detector")


class _QuietEndpoints(logging.Filter):
    """Drop access-log lines for the high-frequency endpoints.

    A DoS run ingests ~150 events/second and the dashboard polls twice a
    second; logging every one buries the detection output and slows the
    terminal down. Everything else still logs normally.
    """

    NOISY = ("/logs", "/stats", "/events", "/static", "/config")

    def filter(self, record: logging.LogRecord) -> bool:
        return not any(path in record.getMessage() for path in self.NOISY)


logging.getLogger("uvicorn.access").addFilter(_QuietEndpoints())

STATIC_DIR = Path(__file__).parent / "static"


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _naive_utc(dt: datetime) -> datetime:
    """Store all timestamps as naive UTC so SQLite comparisons stay consistent."""
    if dt.tzinfo is not None:
        dt = dt.astimezone(timezone.utc).replace(tzinfo=None)
    return dt


# ---------------------------------------------------------------------------
# Detection loop
# ---------------------------------------------------------------------------

# Small grace period so requests still in flight land before their window is
# processed. Without it the tail of each window would be missed.
INGEST_LAG_SECONDS = 1.0


def process_window(session: Session, start: datetime, end: datetime) -> int:
    """Run the full pipeline over one window. Returns the number of detections.

    Feature extraction -> rules AND ML (both always evaluated) -> events.
    """
    features = compute_window(session, start, end)
    if not features:
        return 0

    scores = detector.score([feature_vector(f) for f in features])

    detections = 0
    for feat, ml_score in zip(features, scores):
        rule_flag, rule_type = apply_rules(feat)
        # The score is always computed, but a window needs enough requests
        # before the model is allowed to turn it into an alert.
        ml_flag = (
            detector.is_anomalous(ml_score) and feat.req_count >= ML_MIN_REQ_COUNT
        )

        # An event is recorded when EITHER detector fires, and always carries
        # both verdicts -- the hybrid result is never collapsed into one.
        if not (rule_flag or ml_flag):
            continue

        session.add(
            Event(
                ts=feat.window_end,
                ip=feat.ip,
                endpoint=feat.top_endpoint,
                rule_flag=rule_flag,
                rule_type=rule_type,
                ml_score=ml_score,
                ml_flag=ml_flag,
                req_count=feat.req_count,
                fail_rate=feat.fail_rate,
                feature_id=feat.id,
            )
        )
        detections += 1
        log.info(
            "DETECTION ip=%s req=%d fail=%.2f rule=%s ml=%.3f%s",
            feat.ip, feat.req_count, feat.fail_rate,
            rule_type if rule_flag else "none", ml_score,
            " [ML]" if ml_flag else "",
        )

    return detections


async def detection_loop() -> None:
    """Every WINDOW_SECONDS: build features, detect, and periodically retrain."""
    # Start from the current instant so we never reprocess old history on boot.
    next_start = utcnow()
    last_retrain = utcnow()
    log.info(
        "Detection loop started (window=%ds, dos>%d, brute fail>%.2f & req>=%d, "
        "ml>%.2f)",
        WINDOW_SECONDS, DOS_REQ_COUNT, BRUTE_FAIL_RATE, BRUTE_MIN_REQ,
        ML_SCORE_THRESHOLD,
    )

    while True:
        try:
            await asyncio.sleep(1.0)
            now = utcnow()

            # Process every window that has fully closed (plus the ingest lag).
            while next_start + timedelta(
                seconds=WINDOW_SECONDS + INGEST_LAG_SECONDS
            ) <= now:
                window_end = next_start + timedelta(seconds=WINDOW_SECONDS)
                session = SessionLocal()
                try:
                    process_window(session, next_start, window_end)
                    session.commit()
                except Exception:
                    session.rollback()
                    log.exception("Window processing failed")
                finally:
                    session.close()
                next_start = window_end

            # Periodic refit on clean (non-rule-flagged) live traffic.
            if (now - last_retrain).total_seconds() >= RETRAIN_INTERVAL:
                last_retrain = now
                session = SessionLocal()
                try:
                    detector.retrain_from_db(session)
                except Exception:
                    log.exception("Retrain failed")
                finally:
                    session.close()

        except asyncio.CancelledError:
            log.info("Detection loop stopped.")
            raise
        except Exception:
            log.exception("Detection loop error")


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    detector.load_or_bootstrap()
    task = asyncio.create_task(detection_loop())
    yield
    task.cancel()
    try:
        await task
    except asyncio.CancelledError:
        pass


app = FastAPI(
    title="Cybersecurity Log Analysis & Attack Detection System",
    description="Hybrid rule-based + IsolationForest detection over streaming logs.",
    version="1.0.0",
    lifespan=lifespan,
)


# ---------------------------------------------------------------------------
# Ingestion
# ---------------------------------------------------------------------------

@app.post("/logs", response_model=LogAccepted, tags=["ingestion"])
def ingest_log(payload: LogIn, session: Session = Depends(get_session)):
    """Accept and persist a single normalized log event."""
    row = Log(
        ts=_naive_utc(payload.timestamp) if payload.timestamp else utcnow(),
        ip=payload.ip,
        user=payload.user,
        endpoint=payload.endpoint,
        status=payload.status,
        bytes=payload.bytes,
        layer=payload.layer,
    )
    session.add(row)
    session.commit()
    return LogAccepted(ok=True, id=row.id)


# ---------------------------------------------------------------------------
# Dashboard API
# ---------------------------------------------------------------------------

@app.get("/events", response_model=List[EventOut], tags=["dashboard"])
def recent_events(
    limit: int = Query(50, ge=1, le=500),
    session: Session = Depends(get_session),
):
    """Most recent detections, newest first."""
    return (
        session.query(Event)
        .order_by(Event.ts.desc(), Event.id.desc())
        .limit(limit)
        .all()
    )


@app.get("/stats", response_model=StatsOut, tags=["dashboard"])
def stats(session: Session = Depends(get_session)):
    """Aggregates powering the charts and counters."""
    now = utcnow()
    cutoff = now - timedelta(seconds=STATS_WINDOW_SECONDS)

    # Requests per second over the recent window, with empty seconds filled in
    # so the chart line stays continuous.
    per_second = dict(
        session.query(
            func.strftime("%Y-%m-%dT%H:%M:%S", Log.ts).label("sec"),
            func.count(Log.id),
        )
        .filter(Log.ts >= cutoff)
        .group_by("sec")
        .all()
    )
    series: List[RpsPoint] = []
    base = now.replace(microsecond=0)
    for offset in range(STATS_WINDOW_SECONDS, 0, -1):
        moment = base - timedelta(seconds=offset)
        key = moment.strftime("%Y-%m-%dT%H:%M:%S")
        # Emit UTC ISO strings and let the browser localise them, so the chart
        # axis and the events table always show the same clock.
        series.append(RpsPoint(t=key, count=per_second.get(key, 0)))

    # Current rate: average over the last few seconds, which is steadier than
    # a single-second sample.
    recent = (
        session.query(func.count(Log.id))
        .filter(Log.ts >= now - timedelta(seconds=WINDOW_SECONDS))
        .scalar()
        or 0
    )

    top_ips = [
        TopIP(ip=ip, count=count)
        for ip, count in session.query(Log.ip, func.count(Log.id))
        .filter(Log.ts >= cutoff)
        .group_by(Log.ip)
        .order_by(func.count(Log.id).desc())
        .limit(5)
        .all()
    ]

    # Rule-confirmed attacks and ML-only suspicions are counted separately: a
    # confirmed flood is not the same claim as "the model finds this window
    # unusual", and collapsing them would overstate the alert.
    since = now - timedelta(seconds=ACTIVE_ATTACK_SECONDS)
    active_attacks = (
        session.query(func.count(func.distinct(Event.ip)))
        .filter(Event.ts >= since, Event.rule_flag.is_(True))
        .scalar()
        or 0
    )
    rule_ips = session.query(Event.ip).filter(
        Event.ts >= since, Event.rule_flag.is_(True)
    )
    ml_watch = (
        session.query(func.count(func.distinct(Event.ip)))
        .filter(
            Event.ts >= since,
            Event.ml_flag.is_(True),
            Event.ip.notin_(rule_ips),
        )
        .scalar()
        or 0
    )

    return StatsOut(
        rps=series,
        current_rps=round(recent / WINDOW_SECONDS, 1),
        top_ips=top_ips,
        active_attacks=active_attacks,
        ml_watch=ml_watch,
        total_logs=session.query(func.count(Log.id)).scalar() or 0,
        total_events=session.query(func.count(Event.id)).scalar() or 0,
        ml_trained=detector.is_trained,
    )


@app.get("/config", tags=["dashboard"])
def config():
    """Active detection settings -- handy to show during a review."""
    return {
        "window_seconds": WINDOW_SECONDS,
        "rules": describe_rules(),
        "ml": {**detector.info(), "min_req_count": ML_MIN_REQ_COUNT},
    }


@app.get("/health", tags=["dashboard"])
def health():
    return {"status": "ok", "time": utcnow().isoformat()}


# ---------------------------------------------------------------------------
# Dashboard page (served by FastAPI so there is nothing else to run)
# ---------------------------------------------------------------------------

app.mount("/static", StaticFiles(directory=STATIC_DIR), name="static")


@app.get("/", include_in_schema=False)
def dashboard():
    return FileResponse(STATIC_DIR / "index.html")
