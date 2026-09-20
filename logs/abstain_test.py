"""Test script to trigger the ML Abstention Gate.

Sends a moderate amount of anomalous traffic that is suspicious enough to be
flagged by the ML model (>60% probability) but not confident enough to breach
the Alert Threshold (>95%).
"""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logs.common import Counter, make_event, new_session, require_api, send

def main() -> None:
    require_api("Abstention Gate Tester")
    session = new_session()
    counter = Counter("abstention test")
    
    print("Sending moderately suspicious traffic to trigger Abstention Gate...")
    
    # We want to trigger the ML model without triggering the Brute Force rule.
    # Brute force rule is: req_count >= 10 and fail_rate >= 0.70.
    # We will send 8 requests (enough for ML_MIN_REQ_COUNT=5, but below BRUTE_MIN_REQ=10)
    # with a 100% failure rate. This is highly anomalous for a single IP.
    
    ip = "10.0.0.99"
    for _ in range(8):
        event = make_event(
            ip=ip,
            endpoint="/admin/settings",
            status=401,
            user="guest",
            size=250,
            layer="app"
        )
        counter.record(send(session, event))
        time.sleep(0.2)
        
    print("Done. Check the API server logs for an 'ABSTAIN' message.")

if __name__ == "__main__":
    main()
