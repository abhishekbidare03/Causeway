# Cross-Layer Threat Detection & Attribution Platform

An industry-grade cybersecurity pipeline that ingests log events in real time, scores them with a hybrid Rule + Machine Learning ensemble, calibrates the scores to prevent alert fatigue, and correlates the results into topological Incident Graphs mapped to the MITRE ATT&CK framework.

Everything runs locally. No Docker, no cloud services, no database server, no build step.

```text
log generators  ->  POST /logs  ->  SQLite  ->  feature engine (every 5s)
                                                     |
                                          +----------+----------+
                                          |                     |
                                     rule engine          IsolationForest
                                   (thresholds)          (anomaly score 0-1)
                                          |                     |
                                          +----------+----------+
                                                     |
                                  correlation engine (Entity Graph)
                                                     |
                                   incident records -> live dashboard
```

---

## 1. One-time setup

**Prerequisite:** Python 3.10 or newer (developed and tested on 3.12). Nothing else — no Node.js, no npm, no database server, no Docker.

```bash
cd D:\CSE\major_project
pip install -r requirements.txt
```

That's the entire install. The SQLite database and the trained model file are created automatically on first run, inside `data/`.

### What gets installed, and what doesn't

`requirements.txt` installs seven direct packages: **fastapi**, **uvicorn**, **pydantic**, **sqlalchemy**, **scikit-learn**, **numpy**, **joblib** and **requests**.

Two things people expect to install here but **do not need to**:
- **Chart.js** — A copy already ships with the project at `app/static/chart.umd.min.js`. The dashboard works with **no internet connection**.
- **SQLite** — Built into Python's standard library. There is no database server to install, configure, or start.

---

## 2. Running the one-click demo

You only need **one terminal** to run the entire system.

```bash
uvicorn app.main:app --reload
```

Wait for `Application startup complete`. This one terminal runs the ingestion API, the background detection loops, the correlation engine, and the dashboard.

Open **http://127.0.0.1:8000** in a browser.

### The Simulation Control Panel
You no longer need to type terminal commands to generate attacks. At the top of the dashboard is the **Simulation Controls** bar:

1. Click **Normal Traffic**. You will see the requests/sec chart start moving with benign background noise.
2. Click **Multi-Stage Attack**. The system will simulate a 32-second lateral movement intrusion.
3. Watch the **Active Incidents & Entity Graph** panel. The Correlation Engine will group the raw alerts into a single Kill Chain incident, identifying "Patient Zero" and calculating the Blast Radius.
4. Click **Reset Demo** anytime to wipe the database and start fresh.

---

## 3. Core Enterprise Features

This project was built to solve three specific problems in security operations centers (SOCs): *Visibility Fragmentation, Alert Fatigue, and Absent Attribution.*

### A. Hybrid Detection Engine
Running a single detection model always fails in production. We run two engines side-by-side on a 5-second tumbling window:
- **Sigma Rules (`app/detection/rules.py`):** Deterministic, explainable, and instant. Catches known shapes like DoS floods and basic brute force.
- **Unsupervised ML (`app/detection/ml_model.py`):** An `IsolationForest` model that learns from traffic to catch unusual behavior no rule describes. It automatically bootstraps on startup and retrains itself every 60 seconds on clean traffic.

### B. Platt Scaling & The Abstention Gate
Anomaly models output arbitrary scores that mean nothing to an analyst. We use mathematical calibration (**Platt Scaling**, via a logistic sigmoid function) to convert the Isolation Forest's raw output into a true anomaly probability (0% to 100%).

We raised the hard alert threshold to **0.95**. If traffic falls between 60% and 95%, it hits the **Abstention Gate**. The model actively logs the suspicious behavior for reference but mathematically refuses to trigger a false-positive alert, saving analyst time. You can trigger this yourself by clicking the **Abstention Probe** button.

### C. Correlation & Attribution
Instead of dumping 50 raw alerts on an analyst's desk, the correlation engine (`app/detection/correlation.py`) groups related anomalies into unified **Incidents**. 
- It builds an in-memory directed graph of the attack.
- It identifies **Patient Zero** (the earliest node with no anomalous inbound edge).
- It calculates the **Blast Radius** (forward reachability from patient zero).
- It maps the sequence to the **MITRE ATT&CK** kill chain.

### D. Offline Evaluation Harness
"Accuracy" is a meaningless metric in cybersecurity where 99.9% of traffic is benign. To prove the engine works, we built an offline evaluation harness.
Run the following in a terminal:
```bash
python evaluate.py
```
This script bypasses the web server, loads an offline labeled corpus (`data/corpus.jsonl`), runs the exact production detection loop, and calculates true **Precision and Recall** for each attack class.

---

## 4. API Endpoints

| Endpoint | Purpose |
|---|---|
| `POST /logs` | Ingest one normalized event: `timestamp, ip, user, endpoint, status, bytes, layer` |
| `GET /events` | Recent raw detections, newest first, with both rule and ML verdicts |
| `GET /incidents` | Correlated incident objects, including kill chain and blast radius |
| `GET /stats` | Requests/sec series, top IPs, active attacks, totals |
| `POST /simulate/{name}` | Start a background attack simulation directly from the API |
| `POST /reset` | Safely wipe all database tables for a clean demo restart |
| `GET /docs` | Auto-generated Swagger UI |

---

## 5. Project Structure

```text
app/
  main.py              FastAPI app, detection loops, dashboard API, simulation control
  config.py            Every threshold and tunable, in one place
  db.py                SQLite engine (WAL mode) + sessions
  models.py            ORM: logs / features / events / incidents
  schemas.py           Request & response validation
  features.py          5-second windowed feature extraction
  detection/
    rules.py           Threshold rules
    ml_model.py        IsolationForest: bootstrap, calibrate, score, retrain
    correlation.py     Entity graph, MITRE mapping, and incident grouping
  static/
    index.html         The dashboard (single page, zero build step)
logs/
  generator.py         Normal traffic
  lateral_movement.py  Multi-stage correlation test
  abstain_probe.py     Tests the ML Abstention Gate
evaluate.py            Offline evaluation harness for precision/recall
data/                  Created at runtime: logs.db, model.pkl, corpus.jsonl
```
