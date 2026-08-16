"""ML-based detection: unsupervised anomaly scoring with IsolationForest.

This is the second half of the hybrid engine. It learns what normal traffic
looks like statistically and scores how far each new feature vector sits from
that baseline -- so it can flag odd behaviour nobody wrote a rule for.

Three details worth explaining at review time:

1. Bootstrapping. On first start there is no traffic history, so the model is
   fitted on synthetic *normal* vectors drawn from the same distribution the
   traffic generator produces. Scores are therefore meaningful from the very
   first window instead of needing a warm-up.

2. Score calibration. IsolationForest's raw decision_function has a very narrow
   dynamic range (roughly -0.04 to +0.24 here), so a fixed sigmoid squashes
   normal and attack traffic into indistinguishable numbers. Instead the raw
   anomaly score is calibrated against the training distribution, anchored so
   that the model's own outlier boundary maps exactly to ML_SCORE_THRESHOLD.
   The published 0-1 score therefore means something concrete: above the
   threshold is precisely what IsolationForest itself calls an outlier.

3. Clean retraining. Periodic retraining uses only feature rows the rule engine
   did NOT flag. If attack traffic were folded back into the baseline, the model
   would gradually learn to consider floods normal.
"""

import logging
import threading
from typing import List, Optional, Sequence

import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import StandardScaler
from sqlalchemy.orm import Session

from app.config import (
    ML_CONTAMINATION,
    ML_MAX_SAMPLES,
    ML_N_ESTIMATORS,
    ML_RANDOM_STATE,
    ML_SCORE_THRESHOLD,
    MODEL_PATH,
    RETRAIN_MAX_SAMPLES,
    RETRAIN_MIN_SAMPLES,
)
from app.features import FEATURE_COLUMNS
from app.models import Event, Feature

log = logging.getLogger("detector.ml")

# Response-size profile of normal traffic, mirroring logs/generator.py: tiny
# health checks, ordinary pages, and the occasional large static asset.
RESPONSE_SIZES = np.array(
    [4200, 5100, 8800, 3400, 1900, 6200, 2700, 850, 15400, 120], dtype=float
)
_w = np.array([10, 8, 9, 5, 4, 5, 2, 3, 6, 2], dtype=float)
RESPONSE_WEIGHTS = _w / _w.sum()


def _build_pipeline() -> Pipeline:
    """Scaling matters here: req_count reaches the hundreds and bytes_sum the
    hundred-thousands, while fail_rate is bounded at 1.0. Without
    standardisation the forest would effectively see only the large columns.
    """
    return Pipeline(
        [
            ("scale", StandardScaler()),
            (
                "iforest",
                IsolationForest(
                    n_estimators=ML_N_ESTIMATORS,
                    max_samples=ML_MAX_SAMPLES,
                    contamination=ML_CONTAMINATION,
                    random_state=ML_RANDOM_STATE,
                ),
            ),
        ]
    )


def synthetic_normal(n: int = 600, seed: int = ML_RANDOM_STATE) -> np.ndarray:
    """Generate plausible *normal* feature vectors for the cold-start fit.

    Mirrors what logs/generator.py produces: a handful of requests per IP per
    window, few failures, a couple of distinct endpoints, relaxed pacing.
    """
    rng = np.random.default_rng(seed)

    # A mixture, not a single Poisson: most windows are a few requests, but a
    # real user occasionally bursts (a page pulling many assets at once). The
    # heavier tail keeps ordinary bursts from being scored as anomalies.
    quiet = rng.poisson(3.0, n) + 1
    bursty = rng.poisson(10.0, n) + 1
    req_count = np.clip(
        np.where(rng.random(n) < 0.85, quiet, bursty), 1, 30
    ).astype(float)

    # Failures are drawn as actual binomial outcomes rather than a flat ratio.
    # This matters: a window holding one request that happened to 404 has
    # fail_rate 1.0, which is perfectly normal and must not look like a brute
    # force. What stays rare -- and therefore anomalous -- is a high failure
    # rate sustained over *many* requests.
    p_fail = rng.uniform(0.0, 0.15, n)
    fail_rate = rng.binomial(req_count.astype(int), p_fail) / req_count

    unique_endpoints = np.minimum(
        req_count, np.clip(rng.poisson(2.0, n) + 1, 1, 8)
    ).astype(float)

    # Human-paced browsing: a few hundred milliseconds up to the full window.
    avg_interarrival = np.where(req_count > 1, rng.uniform(0.35, 5.0, n), 5.0)

    # Payload sizes are drawn from the same profile the traffic generator uses
    # (a health check is ~120 bytes, a JS bundle ~15 KB). Assuming a narrow
    # per-request size here makes the model flag any window containing a large
    # asset, which is a false positive we actually hit in testing.
    max_req = int(req_count.max())
    draws = rng.choice(
        RESPONSE_SIZES, size=(n, max_req), p=RESPONSE_WEIGHTS
    ) * rng.uniform(0.6, 1.4, (n, max_req))
    active = np.arange(max_req)[None, :] < req_count[:, None]
    bytes_sum = (draws * active).sum(axis=1)

    return np.column_stack(
        [req_count, fail_rate, unique_endpoints, avg_interarrival, bytes_sum]
    )


class MLDetector:
    """Holds the fitted pipeline and converts its output into a 0-1 score."""

    def __init__(self) -> None:
        self._pipeline: Optional[Pipeline] = None
        # Calibration anchors, derived from the training set at fit time.
        self._s_median = 0.0   # typical normal anomaly level -> score 0
        self._s_boundary = 1.0  # model's outlier boundary   -> score = threshold
        self._lock = threading.Lock()
        self.trained_on = 0
        self.source = "untrained"

    # --- state -----------------------------------------------------------
    @property
    def is_trained(self) -> bool:
        return self._pipeline is not None

    def info(self) -> dict:
        return {
            "trained": self.is_trained,
            "samples": self.trained_on,
            "source": self.source,
            "features": FEATURE_COLUMNS,
            "threshold": ML_SCORE_THRESHOLD,
        }

    # --- training --------------------------------------------------------
    def _fit(self, matrix: np.ndarray, source: str) -> None:
        pipeline = _build_pipeline()
        pipeline.fit(matrix)

        # sklearn returns negated anomaly scores; flip so higher = stranger.
        train_scores = -pipeline.score_samples(matrix)
        s_median = float(np.median(train_scores))
        # offset_ is the contamination-derived cut-off: decision_function is
        # score_samples - offset_, so -offset_ is the boundary in our sign.
        s_boundary = float(-pipeline.named_steps["iforest"].offset_)
        if s_boundary <= s_median:  # degenerate data guard
            s_boundary = s_median + 1e-6

        with self._lock:
            self._pipeline = pipeline
            self._s_median = s_median
            self._s_boundary = s_boundary
            self.trained_on = len(matrix)
            self.source = source

    def load_or_bootstrap(self) -> None:
        """Restore a persisted model, or cold-start one from synthetic normals."""
        if MODEL_PATH.exists():
            try:
                bundle = joblib.load(MODEL_PATH)
                if bundle.get("features") != FEATURE_COLUMNS:
                    raise ValueError("feature layout changed")
                with self._lock:
                    self._pipeline = bundle["pipeline"]
                    self._s_median = bundle["s_median"]
                    self._s_boundary = bundle["s_boundary"]
                    self.trained_on = bundle.get("samples", 0)
                    self.source = bundle.get("source", "disk")
                log.info(
                    "Loaded IsolationForest from %s (%d samples, source=%s)",
                    MODEL_PATH.name, self.trained_on, self.source,
                )
                return
            except Exception as exc:  # corrupt, stale, or version-mismatched
                log.warning("Could not load %s (%s) -- retraining.", MODEL_PATH, exc)

        self._fit(synthetic_normal(), "bootstrap-synthetic")
        self._persist()
        log.info(
            "Bootstrapped IsolationForest on %d synthetic normal vectors.",
            self.trained_on,
        )

    def _persist(self) -> None:
        try:
            joblib.dump(
                {
                    "pipeline": self._pipeline,
                    "s_median": self._s_median,
                    "s_boundary": self._s_boundary,
                    "samples": self.trained_on,
                    "source": self.source,
                    "features": FEATURE_COLUMNS,
                },
                MODEL_PATH,
            )
        except Exception as exc:
            log.warning("Could not persist model: %s", exc)

    def retrain_from_db(self, session: Session) -> bool:
        """Refit on recent feature rows that the rule engine did not flag.

        Returns True if a retrain actually happened.
        """
        flagged = (
            session.query(Event.feature_id)
            .filter(Event.rule_flag.is_(True), Event.feature_id.isnot(None))
            .subquery()
        )
        rows = (
            session.query(
                Feature.req_count,
                Feature.fail_rate,
                Feature.unique_endpoints,
                Feature.avg_interarrival,
                Feature.bytes_sum,
            )
            .filter(Feature.id.notin_(session.query(flagged.c.feature_id)))
            .order_by(Feature.id.desc())
            .limit(RETRAIN_MAX_SAMPLES)
            .all()
        )

        if len(rows) < RETRAIN_MIN_SAMPLES:
            return False

        matrix = np.array([[float(v) for v in row] for row in rows], dtype=float)
        self._fit(matrix, "live-clean-traffic")
        self._persist()
        log.info("Retrained IsolationForest on %d clean windows.", len(matrix))
        return True

    # --- inference -------------------------------------------------------
    def score(self, vectors: Sequence[Sequence[float]]) -> List[float]:
        """Map feature vectors to anomaly scores in [0, 1] (higher = stranger).

        Piecewise-linear against the training distribution:
            median normal          -> 0.0
            model outlier boundary -> ML_SCORE_THRESHOLD
            one span beyond that   -> 1.0
        """
        if not vectors:
            return []

        with self._lock:
            pipeline = self._pipeline
            s_median = self._s_median
            s_boundary = self._s_boundary
        if pipeline is None:
            return [0.0] * len(vectors)

        raw = -pipeline.score_samples(np.asarray(vectors, dtype=float))
        span = s_boundary - s_median

        below = ML_SCORE_THRESHOLD * (raw - s_median) / span
        above = ML_SCORE_THRESHOLD + (1.0 - ML_SCORE_THRESHOLD) * (
            raw - s_boundary
        ) / span
        scores = np.where(raw <= s_boundary, below, above)
        return [round(float(s), 3) for s in np.clip(scores, 0.0, 1.0)]

    @staticmethod
    def is_anomalous(score: float) -> bool:
        return score > ML_SCORE_THRESHOLD


# Single shared instance used by the detection loop.
detector = MLDetector()
