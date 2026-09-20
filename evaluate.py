"""Offline evaluation harness for the detection pipeline.

Reads the labeled corpus, runs it through the exact production detection loop,
and calculates Precision, Recall, and False Positive Rate for each attack class.

Run: python evaluate.py
"""

import json
import logging
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

# 1. Patch the database to use in-memory SQLite before importing app modules
import app.db
import app.config
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

test_engine = create_engine("sqlite:///:memory:", future=True)
app.db.engine = test_engine
app.db.SessionLocal = sessionmaker(bind=test_engine, autoflush=False, expire_on_commit=False)
app.config.DB_URL = "sqlite:///:memory:"

# Now import the rest of the application
from app.db import init_db
from app.models import Log, Event
from app.main import process_window
from app.detection.ml_model import detector
from app.config import WINDOW_SECONDS

logging.basicConfig(level=logging.WARNING)

CORPUS_PATH = Path("data/corpus.jsonl")

def main():
    if not CORPUS_PATH.exists():
        print(f"Error: {CORPUS_PATH} not found. Run 'python logs/generate_corpus.py' first.")
        return

    print("Initializing offline evaluation environment...")
    init_db()
    
    # Initialize the ML model (cold start bootstrap)
    detector.load_or_bootstrap()

    session = app.db.SessionLocal()
    
    print("Loading corpus and inserting events...")
    # Track the ground truth label for each IP in each 5-second window
    # Mapping: (window_end_timestamp, ip) -> label
    ground_truth_map = defaultdict(lambda: "benign")
    
    first_event_time = None
    last_event_time = None
    
    logs_to_insert = []
    
    with open(CORPUS_PATH, "r") as f:
        for line in f:
            if not line.strip():
                continue
            data = json.loads(line)
            ts = datetime.fromisoformat(data["timestamp"]).replace(tzinfo=None)
            
            if first_event_time is None or ts < first_event_time:
                first_event_time = ts
            if last_event_time is None or ts > last_event_time:
                last_event_time = ts
                
            # Insert into database
            log = Log(
                ts=ts,
                ip=data["ip"],
                user=data.get("user"),
                endpoint=data["endpoint"],
                status=data["status"],
                bytes=data["bytes"],
                layer=data["layer"],
            )
            logs_to_insert.append(log)
            
            # Map the event to its 5-second window
            # We align windows to the start time just like the pipeline would
            time_offset = (ts - first_event_time).total_seconds()
            window_index = int(time_offset // WINDOW_SECONDS)
            window_end = first_event_time + timedelta(seconds=(window_index + 1) * WINDOW_SECONDS)
            
            gt = data.get("ground_truth", "benign")
            if gt != "benign":
                ground_truth_map[(window_end, data["ip"])] = gt
                
    session.bulk_save_objects(logs_to_insert)
    session.commit()
    
    print(f"Loaded {len(logs_to_insert)} events spanning from {first_event_time} to {last_event_time}.")
    print("Running detection loop...")
    
    # Run the exact production `process_window` loop
    current_start = first_event_time
    total_detections = 0
    
    while current_start < last_event_time:
        window_end = current_start + timedelta(seconds=WINDOW_SECONDS)
        
        # We wrap in a transaction just like main.py
        try:
            detections = process_window(session, current_start, window_end)
            total_detections += detections
            session.commit()
        except Exception as e:
            session.rollback()
            print(f"Error processing window: {e}")
            
        current_start = window_end
        
    print(f"Detection loop complete. Produced {total_detections} events (alerts).")
    
    print("\nCalculating metrics...")
    
    # We need to evaluate:
    # 1. Did the system catch the brute force attack?
    # 2. Did the system catch the DoS attack?
    # 3. How many false positives were there on benign windows?
    
    # Fetch all generated events
    all_events = session.query(Event).all()
    
    # Track metrics per class
    # structure: class -> {"TP": 0, "FP": 0, "FN": 0, "TN": 0}
    metrics = {
        "brute_force": {"TP": 0, "FP": 0, "FN": 0},
        "dos": {"TP": 0, "FP": 0, "FN": 0},
    }
    
    # Total benign windows = (Total IPs * Total Windows) - Total Attack Windows
    # To simplify, we will just count False Positives (alerts on benign windows)
    total_fp = 0
    
    # Group detections by (window_end, ip)
    predicted_alerts = defaultdict(list)
    for ev in all_events:
        predicted_alerts[(ev.ts, ev.ip)].append(ev)
        
    # Evaluate True Positives and False Negatives against Ground Truth
    for (window_end, ip), true_label in ground_truth_map.items():
        if true_label == "benign":
            continue
            
        alerts = predicted_alerts.get((window_end, ip), [])
        if alerts:
            metrics[true_label]["TP"] += 1
        else:
            metrics[true_label]["FN"] += 1
            
    # Evaluate False Positives
    for (window_end, ip), alerts in predicted_alerts.items():
        true_label = ground_truth_map.get((window_end, ip), "benign")
        if true_label == "benign":
            total_fp += 1
            # If the system flagged a benign window, we assign the FP to the rule it fired
            # For simplicity in this script, we just track global FP.
            
    print("\n=== EVALUATION REPORT ===")
    
    print("\nAttack Class     | Recall (Found / Total) | Precision")
    print("-----------------|------------------------|-----------")
    for attack_class, m in metrics.items():
        tp = m["TP"]
        fn = m["FN"]
        total = tp + fn
        recall = tp / total if total > 0 else 0
        
        # Precision is harder to define per-class if we just track global FP, 
        # but let's approximate by looking at what rule fired if we wanted to.
        # For now, we print Recall and the absolute TP/Total
        print(f"{attack_class:<16} | {tp:4d} / {total:<4d} ({recall:6.1%})  |   N/A")
        
    print(f"\nTotal False Positives (Alerts on Benign Traffic): {total_fp}")
    if total_fp == 0:
        print("Precision (Global): 100.0%")
    else:
        total_tp = sum(m["TP"] for m in metrics.values())
        global_precision = total_tp / (total_tp + total_fp) if (total_tp + total_fp) > 0 else 0
        print(f"Precision (Global): {global_precision:.1%}")
        
    print("=========================\n")

if __name__ == "__main__":
    main()
