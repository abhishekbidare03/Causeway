"""Generates a labeled offline corpus of traffic for evaluation.

This script simulates normal traffic and injects a Brute Force and DoS attack
at specific time windows. It writes events directly to a JSONL file without
making any network calls.

Run: python logs/generate_corpus.py
"""

import json
import os
import random
import sys
from datetime import datetime, timedelta, timezone

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logs.common import make_event
from logs.generator import CLIENT_IPS, ENDPOINTS, ENDPOINT_WEIGHTS, USERS, pick_status

# Ensure data directory exists
os.makedirs("data", exist_ok=True)
CORPUS_PATH = "data/corpus.jsonl"

def main():
    print(f"Generating offline evaluation corpus at {CORPUS_PATH}...")
    
    start_time = datetime.now(timezone.utc).replace(hour=10, minute=0, second=0, microsecond=0)
    
    # Timeline strategy:
    # 0 - 5 mins: Normal traffic
    # 5 - 7 mins: Brute Force attack
    # 7 - 10 mins: Normal traffic
    # 10 - 12 mins: DoS attack
    # 12 - 15 mins: Normal traffic
    
    total_minutes = 15
    events = []
    
    brute_force_ip = "45.83.91.207"
    dos_ip = "185.220.101.44"
    
    # 1. Generate Normal Traffic for the whole 15 minutes
    # ~7 requests/sec * 60 = 420 requests/minute
    normal_reqs = total_minutes * 420
    
    print(f"  Generating {normal_reqs} normal events...")
    for i in range(normal_reqs):
        # Distribute randomly over the 15 minutes
        offset_seconds = random.uniform(0, total_minutes * 60)
        event_time = start_time + timedelta(seconds=offset_seconds)
        
        endpoint, layer, _weight, size = random.choices(
            ENDPOINTS, weights=ENDPOINT_WEIGHTS, k=1
        )[0]
        status = pick_status(endpoint)
        if status >= 400:
            payload_size = random.randint(320, 900)
        else:
            payload_size = int(size * random.uniform(0.6, 1.4))
            
        event = make_event(
            ip=random.choice(CLIENT_IPS),
            endpoint=endpoint,
            status=status,
            user=random.choice(USERS),
            size=payload_size,
            layer=layer,
            ground_truth="benign",
            timestamp=event_time.isoformat()
        )
        events.append(event)
        
    # 2. Inject Brute Force Attack (5 - 7 mins)
    # ~7 requests/sec = 420 requests/minute -> 840 requests over 2 mins
    print("  Injecting Brute Force attack...")
    bf_start = start_time + timedelta(minutes=5)
    bf_end = start_time + timedelta(minutes=7)
    bf_duration = (bf_end - bf_start).total_seconds()
    
    bf_reqs = 840
    for i in range(bf_reqs):
        offset = random.uniform(0, bf_duration)
        event_time = bf_start + timedelta(seconds=offset)
        status = 200 if random.random() < 0.05 else 401
        
        event = make_event(
            ip=brute_force_ip,
            endpoint="/login",
            status=status,
            user=random.choice(USERS),
            size=180 if status == 401 else 940,
            layer="iam",
            ground_truth="brute_force",
            timestamp=event_time.isoformat()
        )
        events.append(event)
        
    # 3. Inject DoS Attack (10 - 12 mins)
    # ~150 requests/sec = 9000 requests/minute -> 18000 requests over 2 mins
    print("  Injecting DoS attack...")
    dos_start = start_time + timedelta(minutes=10)
    dos_end = start_time + timedelta(minutes=12)
    dos_duration = (dos_end - dos_start).total_seconds()
    
    dos_reqs = 18000
    for i in range(dos_reqs):
        offset = random.uniform(0, dos_duration)
        event_time = dos_start + timedelta(seconds=offset)
        
        event = make_event(
            ip=dos_ip,
            endpoint="/api/orders",
            status=200,
            user=None,
            size=310,
            layer="network",
            ground_truth="dos",
            timestamp=event_time.isoformat()
        )
        events.append(event)
        
    # Sort all events chronologically
    print("  Sorting events chronologically...")
    events.sort(key=lambda x: x["timestamp"])
    
    # Write to JSONL
    print(f"  Writing {len(events)} events to {CORPUS_PATH}...")
    with open(CORPUS_PATH, "w") as f:
        for ev in events:
            f.write(json.dumps(ev) + "\n")
            
    print("Done!")

if __name__ == "__main__":
    main()
