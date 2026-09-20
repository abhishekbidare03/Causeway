# Cross-Layer Threat Detection & Attribution Platform

![Python 3.10+](https://img.shields.io/badge/python-3.10+-blue.svg)
![FastAPI](https://img.shields.io/badge/FastAPI-005571?style=flat&logo=fastapi)
![scikit-learn](https://img.shields.io/badge/scikit--learn-%23F7931E.svg?style=flat&logo=scikit-learn&logoColor=white)

An industry-grade cybersecurity platform that ingests security telemetry in real-time, scores events using a hybrid detection ensemble, mathematically calibrates scores to prevent alert fatigue, and correlates disparate alerts into unified Kill Chain incidents.

## Table of Contents
- [Architecture Overview](#architecture-overview)
- [Core Features](#core-features)
- [Quickstart](#quickstart)
- [Interactive Dashboard](#interactive-dashboard)
- [Offline Evaluation](#offline-evaluation)
- [API Reference](#api-reference)

---

## Architecture Overview

The system processes telemetry through a four-stage pipeline designed for production constraints:

1. **Ingestion & Feature Extraction:** High-throughput streaming ingestion with tumbling 5-second window aggregations (e.g., failure rates, volume, geographic novelty).
2. **Hybrid Detection Ensemble:** 
   - **Deterministic:** Sigma-style rules for high-precision catching of known signatures.
   - **Unsupervised ML:** `IsolationForest` continuously learns from baseline traffic to catch zero-day behaviors.
3. **Calibration & Abstention:** Employs Platt Scaling to convert arbitrary anomaly scores into true probabilities. Implements an **Abstention Gate** that suppresses low-confidence machine learning alerts to drastically reduce False Positive rates.
4. **Correlation & Attribution:** Builds an in-memory topological entity graph to group related anomalies, identify "Patient Zero", calculate the blast radius, and map sequences to the MITRE ATT&CK framework.

---

## Core Features

- **Real-Time Stream Processing:** Ingests and processes distributed logs asynchronously without blocking.
- **Mathematical Calibration:** Solves the base-rate fallacy inherent in security tooling.
- **Topological Entity Graph:** Replaces alert dumps with contextual, causal incident narratives.
- **Self-Healing ML:** The model automatically bootstraps on startup and retrains itself exclusively on clean windows to prevent baseline poisoning.
- **Zero-Dependency Architecture:** Entirely self-contained. Runs locally with built-in SQLite (WAL mode) and vendored frontend assets. No external database or Docker required.

---

## Quickstart

### Installation

Clone the repository and install the Python dependencies.

```bash
git clone https://github.com/abhishekbidare03/Causeway.git
cd Causeway
pip install -r requirements.txt
```

### Running the Platform

Start the FastAPI application server:

```bash
uvicorn app.main:app --host 127.0.0.1 --port 8000
```
*Note: The SQLite database (`logs.db`) and ML model (`model.pkl`) are initialized automatically inside `data/` on the first run.*

---

## Interactive Dashboard

Navigate to **http://127.0.0.1:8000** to access the Threat Attribution Console.

The dashboard includes a built-in **Simulation Control Panel** for presentation and testing. You can trigger live traffic generation directly from the UI:
- **Normal Traffic:** Simulates benign background telemetry.
- **Multi-Stage Attack:** Executes a simulated lateral movement intrusion, demonstrating the correlation engine's ability to group events into a unified Kill Chain.
- **DoS Flood / Brute Force:** Tests individual detection rules.
- **Abstention Probe:** Tests the ML calibration and abstention gate mechanics.

---

## Offline Evaluation

To prove the efficacy of the detection pipeline, the project includes an offline evaluation harness. It measures True Precision, Recall, and False Positive Rates against a labeled corpus.

```bash
python evaluate.py
```
This script bypasses the web interface, processes the offline corpus through the exact production detection loop, and outputs a statistical evaluation report.

---

## API Reference

The platform exposes a full REST API for headless operation and SIEM integration.

| Method | Endpoint | Description |
|--------|----------|-------------|
| `POST` | `/logs` | Ingest normalized event: `timestamp, ip, user, endpoint, status, bytes, layer` |
| `GET`  | `/events` | Fetch raw anomalous events with both Rule and ML verdicts |
| `GET`  | `/incidents` | Fetch correlated incident objects (Kill Chain, Blast Radius, Patient Zero) |
| `GET`  | `/stats` | Fetch real-time ingestion rates and global statistics |
| `POST` | `/simulate/{name}` | Trigger a background attack simulation |
| `POST` | `/reset` | Safely wipe the datastore |

*Detailed schema documentation is available via the Swagger UI at `http://127.0.0.1:8000/docs` while the server is running.*
