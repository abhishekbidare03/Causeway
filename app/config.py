"""Central configuration for the detection pipeline.

Every tunable threshold lives here so it can be explained (and adjusted) in one
place during the project review.
"""

from pathlib import Path

# --- paths ---------------------------------------------------------------
BASE_DIR = Path(__file__).resolve().parent.parent
DATA_DIR = BASE_DIR / "data"
DATA_DIR.mkdir(exist_ok=True)

DB_PATH = DATA_DIR / "logs.db"
DB_URL = f"sqlite:///{DB_PATH}"
MODEL_PATH = DATA_DIR / "model.pkl"

# --- feature extraction --------------------------------------------------
# Width of the tumbling window used to build per-IP feature vectors.
WINDOW_SECONDS = 5

# --- rule-based detection ------------------------------------------------
# DoS: a single IP making more than this many requests inside one window.
# Normal traffic sits at ~2-4 requests per IP per window, a flood at 700+.
DOS_REQ_COUNT = 50

# Brute force: a high ratio of failed requests, with enough volume to be
# meaningful (a single failed login is not an attack).
BRUTE_FAIL_RATE = 0.7
BRUTE_MIN_REQ = 10

# --- ML detection --------------------------------------------------------
# Anomaly probabilities are mapped to [0, 1].
# Above 0.95 triggers a hard alert.
ML_SCORE_THRESHOLD = 0.95
# Above 0.60 but below 0.95 enters the Abstention Gate (logged, but not alerted).
ML_ABSTAIN_THRESHOLD = 0.60

# Minimum requests in a window before the ML model is allowed to raise a flag.
# One or two requests carry no statistical evidence -- a lone 404 gives
# fail_rate 1.0, which looks extreme but means nothing. The score is still
# computed and displayed for every window; only the alert is gated.
ML_MIN_REQ_COUNT = 5

# IsolationForest hyper-parameters.
# contamination sets where the model draws its outlier boundary, and so is the
# real control over the false-positive rate (the 0-1 score is calibrated to
# that boundary, so changing ML_SCORE_THRESHOLD alone would only relabel).
# Measured on recorded traffic: 0.02 -> 1.0% of normal windows flagged,
# 0.01 -> none, while attacks still score ~0.77.
ML_CONTAMINATION = 0.01
ML_N_ESTIMATORS = 200
ML_MAX_SAMPLES = 256
ML_RANDOM_STATE = 42

# Retrain the model every N seconds, provided we have enough clean samples.
RETRAIN_INTERVAL = 60
# Deliberately high: refitting on a thin sample estimates the normal
# distribution badly and produces a burst of false positives. Until this many
# clean windows exist, the synthetic bootstrap model is the better baseline.
RETRAIN_MIN_SAMPLES = 300
RETRAIN_MAX_SAMPLES = 2000

# --- dashboard -----------------------------------------------------------
# Window used by /stats for the requests-per-second chart.
STATS_WINDOW_SECONDS = 60
# An IP with a detection inside this many seconds counts as an active attack.
ACTIVE_ATTACK_SECONDS = 15

# --- log generators ------------------------------------------------------
API_URL = "http://127.0.0.1:8000"
