"""Time-window feature engineering.

Raw log lines are not directly useful to a detector. Every WINDOW_SECONDS the
pipeline groups the window's logs by source IP and reduces them to a small
statistical fingerprint:

    req_count         total requests        -- high  => flood
    fail_rate         failed / total        -- high  => brute force
    unique_endpoints  distinct paths hit    -- high  => scanning
    avg_interarrival  mean gap in seconds   -- low   => automated flood
    bytes_sum         total payload bytes   -- volume of data moved

All five make up the vector fed to the ML model.
"""

from collections import Counter as _Counter
from datetime import datetime
from typing import List

from sqlalchemy.orm import Session

from app.config import WINDOW_SECONDS
from app.models import Feature, Log

# Column order of the ML feature vector. Must stay in sync with ml_model.py.
FEATURE_COLUMNS = [
    "req_count",
    "fail_rate",
    "unique_endpoints",
    "avg_interarrival",
    "bytes_sum",
]


def feature_vector(feat: Feature) -> List[float]:
    """Extract the numeric vector the ML model consumes, in fixed order."""
    return [
        float(feat.req_count),
        float(feat.fail_rate),
        float(feat.unique_endpoints),
        float(feat.avg_interarrival),
        float(feat.bytes_sum),
    ]


def compute_window(session: Session, start: datetime, end: datetime) -> List[Feature]:
    """Build and persist one feature row per active IP in [start, end).

    Returns the newly created (and flushed, so they have ids) Feature rows.
    """
    rows = (
        session.query(Log.ip, Log.ts, Log.endpoint, Log.status, Log.bytes)
        .filter(Log.ts >= start, Log.ts < end)
        .order_by(Log.ip, Log.ts)
        .all()
    )
    if not rows:
        return []

    by_ip: dict[str, list] = {}
    for row in rows:
        by_ip.setdefault(row.ip, []).append(row)

    features: List[Feature] = []
    for ip, entries in by_ip.items():
        req_count = len(entries)
        failures = sum(1 for e in entries if e.status >= 400)
        endpoints = [e.endpoint for e in entries]
        timestamps = [e.ts for e in entries]

        if req_count > 1:
            span = (timestamps[-1] - timestamps[0]).total_seconds()
            avg_interarrival = span / (req_count - 1)
        else:
            # A lone request has no gap to measure; treat it as maximally slow
            # so it never looks like a flood.
            avg_interarrival = float(WINDOW_SECONDS)

        features.append(
            Feature(
                window_start=start,
                window_end=end,
                ip=ip,
                req_count=req_count,
                fail_rate=failures / req_count,
                unique_endpoints=len(set(endpoints)),
                avg_interarrival=avg_interarrival,
                bytes_sum=sum(e.bytes or 0 for e in entries),
                top_endpoint=_Counter(endpoints).most_common(1)[0][0],
            )
        )

    session.add_all(features)
    session.flush()  # assign ids so events can reference them
    return features
