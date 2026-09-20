# Cybersecurity Log Analysis & Attack Detection System

A working end-to-end pipeline that ingests log events in real time, extracts
statistical features over 5-second windows, and detects attacks using **two
detectors running side by side** — fast rule-based thresholds and an
unsupervised IsolationForest anomaly model — with results on a live dashboard.

Everything runs locally. No Docker, no cloud services, no database server, no
build step.

> **Presenting this project?** See **[EXPLAIN.md](EXPLAIN.md)** — a plain-language
> walkthrough and a step-by-step demo script, including what to say at each stage
> and the questions a reviewer is likely to ask.

```
log generators  ->  POST /logs  ->  SQLite  ->  feature engine (every 5s)
                                                     |
                                          +----------+----------+
                                          |                     |
                                     rule engine          IsolationForest
                                   (thresholds)          (anomaly score 0-1)
                                          |                     |
                                          +----------+----------+
                                                     |
                                            events table -> dashboard
```

---

## 1. One-time setup

**Prerequisite:** Python 3.10 or newer (developed and tested on 3.12). Nothing
else — no Node.js, no npm, no database server, no Docker.

```bash
cd D:\CSE\major_project
pip install -r requirements.txt
```

That's the entire install. The SQLite database and the trained model file are
created automatically on first run, inside `data/`.

### What gets installed, and what doesn't

`requirements.txt` installs seven direct packages: **fastapi**, **uvicorn**,
**pydantic**, **sqlalchemy**, **scikit-learn**, **numpy**, **joblib** and
**requests** (pip pulls in their own dependencies automatically).

Two things people expect to install here but **do not need to**:

- **Chart.js** — this is a JavaScript library, not a Python package, so it can
  never appear in `requirements.txt`. A copy already ships with the project at
  `app/static/chart.umd.min.js` (205 KB) and the dashboard loads it from the
  local server. Nothing to install, and the charts work with **no internet
  connection**.
- **SQLite** — built into Python's standard library. There is no database
  server to install, configure, or start.

> Verified: installing this file into an empty virtual environment and running
> the full pipeline from it works end to end, with no additional packages.

### Optional: use a virtual environment

Recommended if your friend has other Python projects, so versions can't clash:

```bash
python -m venv .venv
.venv\Scripts\activate          # Windows
# source .venv/bin/activate     # macOS / Linux
pip install -r requirements.txt
```

---

## 2. Running the demo

Three terminals, all opened in `D:\CSE\major_project`.

### Terminal 1 — the server (start this first)

```bash
uvicorn app.main:app --reload
```

Wait for `Application startup complete`. This one terminal runs the ingestion
API, the detection loop, and the dashboard.

Then open **http://127.0.0.1:8000** in a browser.

> Leave this terminal visible if you can — detections print here live, next to
> the dashboard.

### Terminal 2 — normal background traffic

```bash
python logs/generator.py
```

~7 requests/second spread across 12 client IPs. The dashboard's request-volume
chart settles into a low, steady line. **Active Attacks stays 0** and the
flagged-events table stays empty. Let this run for the whole demo.

### Terminal 3 — the attacks (run one at a time)

```bash
python logs/brute_force.py     # repeated failed logins from one IP
```

Within ~5 seconds: `45.83.91.207` appears in the flagged-events table with rule
verdict **Brute force** and an ML anomaly score around 0.77. Active Attacks
becomes 1.

Stop it with `Ctrl+C`, then:

```bash
python logs/dos_attack.py      # single-IP request flood
```

Within ~5 seconds: the request-volume chart **spikes from ~7/s to ~150/s**, and
`185.220.101.44` appears with rule verdict **DoS flood** plus its own ML score.

Stop everything with `Ctrl+C` in each terminal.

---

## 3. What to point at during the review

| On screen | The point to make |
|---|---|
| Request-volume chart | The flood is visible instantly — ~7/s to ~150/s |
| Active Attacks badge | Counts **rule-confirmed** attacks only; ML-only findings are reported beneath it as the weaker claim they are |
| Rule verdict column | Deterministic, explainable, instant — but only catches shapes we encoded |
| ML anomaly score column | Learned from traffic, catches unusual behaviour no rule describes |
| A row where the two disagree | This is the whole argument for hybrid detection — see below |
| Server terminal | Detections stream live as they happen |

**The best moment to look for — the ramp-up window.** The first window of an
attack is where the two detectors disagree, and both directions show up in
practice:

- **ML catches what the rule misses.** The first brute-force window often holds
  ~9 failed logins — just under the rule's `req_count >= 10` threshold, so the
  rule verdict reads *no rule match*, while the ML score sits around 0.73 and
  flags it. A rule-only system would have missed that window entirely.
- **The rule catches it faster.** Early in a DoS ramp-up the volume rule fires
  immediately while the ML score can still be below threshold (blue meter, no
  ANOMALY tag).

Either row makes the case for running both detectors better than any slide.
Steady-state windows show both firing together.

---

## 4. How detection works

### Features (computed per IP, every 5 seconds)

| Feature | Meaning | Attack signal |
|---|---|---|
| `req_count` | requests in the window | high = flood |
| `fail_rate` | failed (HTTP >= 400) / total | high = brute force |
| `unique_endpoints` | distinct paths touched | high = scanning |
| `avg_interarrival` | mean gap between requests | low = automated |
| `bytes_sum` | total payload bytes | volume of data moved |

All five are stored in the `features` table and are the input vector to the ML
model.

### Rule engine (`app/detection/rules.py`)

| Rule | Condition |
|---|---|
| DoS | `req_count > 50` in one window |
| Brute force | `fail_rate > 0.7` **AND** `req_count >= 10` |

Brute force is checked first: a high failure rate is a more specific signature
than volume alone.

### ML model (`app/detection/ml_model.py`)

IsolationForest inside a `StandardScaler` pipeline, producing a 0–1 anomaly
score. Three design points worth defending:

1. **Cold start.** On first run there is no traffic history, so the model is
   fitted on synthetic *normal* feature vectors drawn from the same profile the
   generator produces. Scores are meaningful from the first window — no warm-up
   period mid-demo.
2. **Score calibration.** IsolationForest's raw `decision_function` has a very
   narrow range (about −0.04 to +0.24 here), so a naive sigmoid squashes normal
   and attack traffic into indistinguishable numbers — measured, not assumed.
   Instead the score is calibrated against the training distribution so that
   the model's own outlier boundary maps exactly to the flag threshold. A score
   above 0.7 means precisely "IsolationForest classifies this as an outlier".
3. **Clean retraining.** Every 60 seconds the model refits on recent feature
   rows that the **rule engine did not flag**, so attack traffic can never be
   absorbed into the definition of normal. It waits for 300 clean windows
   first — refitting on a thin sample estimates the distribution badly and
   causes a burst of false positives.

A minimum-support gate (`req_count >= 5`) stops the model raising alerts on
windows with too little evidence: a single request that happens to 404 has
`fail_rate` 1.0, which looks extreme but means nothing. The score is still
computed and shown for every window — only the alert is gated.

### Tuning record

Measured on recorded traffic, `contamination` — not the score threshold — is
what controls the false-positive rate, because the score is calibrated to the
model's own boundary:

| contamination | normal windows flagged | attacks caught |
|---|---|---|
| 0.02 | 3 / 301 (1.0%) | all |
| **0.01 (chosen)** | **0 / 301** | **all** |

All thresholds live in `app/config.py`, and the running values are shown in the
dashboard footer.

---

## 5. API

| Endpoint | Purpose |
|---|---|
| `POST /logs` | Ingest one normalized event: `timestamp, ip, user, endpoint, status, bytes, layer` |
| `GET /events?limit=50` | Recent detections, newest first, with both verdicts |
| `GET /stats` | Requests/sec series, top IPs, active attacks, totals |
| `GET /config` | Active thresholds and model info |
| `GET /health` | Liveness check |
| `GET /docs` | Auto-generated Swagger UI — useful to show reviewers |

---

## 6. Project structure

```
app/
  main.py              FastAPI app, detection loop, dashboard API
  config.py            every threshold and tunable, in one place
  db.py                SQLite engine (WAL mode) + sessions
  models.py            ORM: logs / features / events
  schemas.py           request & response validation
  features.py          5-second windowed feature extraction
  detection/
    rules.py           threshold rules
    ml_model.py        IsolationForest: bootstrap, calibrate, score, retrain
  static/
    index.html         the dashboard (single page, no build step)
    chart.umd.min.js   Chart.js, vendored locally so it works offline
logs/
  common.py            shared HTTP helper for the simulators
  generator.py         normal traffic
  brute_force.py       brute-force attack
  dos_attack.py        DoS flood
data/                  created at runtime: logs.db, model.pkl
```

### Database schema

- **`logs`** — every ingested event: `ts, ip, user, endpoint, status, bytes, layer`
- **`features`** — one row per IP per 5-second window, holding the five features
- **`events`** — detections, storing `rule_flag`, `rule_type`, `ml_score` and
  `ml_flag` together, so the hybrid result is never collapsed into one verdict

---

## 7. Troubleshooting

| Problem | Fix |
|---|---|
| Attack scripts exit with "could not reach the ingestion API" | Terminal 1 isn't running yet — start the server first |
| Dashboard charts are blank | Hard-refresh (`Ctrl+F5`). Chart.js is served locally, so no internet is needed |
| Want a completely clean slate | Stop the server, delete `data/logs.db` and `data/model.pkl`, restart |
| Port 8000 already in use | `uvicorn app.main:app --reload --port 8080`, then browse to that port |
| Numbers look odd after long idle | The rate chart only covers the last 60 seconds by design |

---

## 8. Next phases (planned, not yet built)

This MVP covers the ingestion → features → hybrid detection → dashboard path.
The remaining stages from the project design document:

| Phase | Scope |
|---|---|
| DDoS detection | Distributed flood from many IPs at once; needs an IP-entropy feature |
| Port scan detection | Rapid sequential access across many endpoints from one source |
| DBSCAN clustering | Group IPs exhibiting similar attack behaviour, for coordinated attacks |
| Correlation engine | Link individual anomalous events into unified **attack sessions** by IP, time window, and endpoint similarity |
| Timeline mapping | Order events chronologically within each session |
| Attack reconstruction | Turn a timeline into a readable story: spike → start, peak → impact, drop → end |
| Risk scoring | `risk = anomaly_score x log(volume) x impact_weight`, for analyst triage |
| Multi-attack support | Handle several concurrent attack types cleanly |

The database schema and the detection loop were built with these in mind: the
`events` table already stores per-window detections keyed by IP and time, which
is exactly the input a correlation engine needs.
