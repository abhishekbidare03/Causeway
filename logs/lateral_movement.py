"""Multi-stage attack simulator: Brute Force -> Lateral Movement -> Exfiltration.

A single attacker IP runs a brute force against /login. Once successful, it
rapidly downloads a massive amount of data from /api/products, triggering
the DoS/Volume rules.

The purpose of this script is to demonstrate the Correlation & Attribution Engine.
Without correlation, this would generate 15 separate alerts.
With correlation, it generates exactly 1 Incident that tells the whole story,
mapping from "Credential Access" to "Impact", and correctly identifying the
Patient Zero IP.

Run: python logs/lateral_movement.py
"""

import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logs.common import Counter, make_event, new_session, require_api, send

ATTACKER_IP = "10.99.88.77"
STAGE_1_TARGET = "/login"
STAGE_2_TARGET = "/api/products"

USERNAMES = ["admin", "root", "test", "postgres", "guest"]

def main() -> None:
    require_api("Multi-Stage Attack Simulator")
    print(f"Attacker IP : {ATTACKER_IP}")
    print("\nStage 1: Brute Force on /login (~15 seconds)")
    print("Stage 2: Successful login & Massive Exfiltration on /api/products (~15 seconds)")
    print("\nExpect: The Correlation Engine will group these into a SINGLE incident.")
    
    session = new_session()
    counter = Counter("multi-stage attack")
    
    try:
        # Stage 1: Brute force
        print("\n--- STAGE 1 STARTING ---")
        stage_1_end = time.time() + 15
        
        while time.time() < stage_1_end:
            # 100% failure rate
            status = 401
            event = make_event(
                ip=ATTACKER_IP,
                endpoint=STAGE_1_TARGET,
                status=status,
                user=random.choice(USERNAMES),
                size=180,
                layer="iam",
            )
            counter.record(send(session, event))
            time.sleep(0.1) # ~10 reqs/sec -> high failure rate triggers brute force
            
        # Transition
        print("\n--- BRUTE FORCE SUCCESSFUL. TRANSITIONING TO DATA EXFILTRATION ---")
        time.sleep(2)
        
        # Stage 2: Data Exfiltration (DoS)
        print("\n--- STAGE 2 STARTING ---")
        stage_2_end = time.time() + 15
        
        while time.time() < stage_2_end:
            # Huge volume, 100% success rate
            event = make_event(
                ip=ATTACKER_IP,
                endpoint=STAGE_2_TARGET,
                status=200,
                user="admin", # using compromised credentials
                size=150000, # downloading huge payloads
                layer="app",
            )
            counter.record(send(session, event))
            time.sleep(0.01) # ~100 reqs/sec -> triggers volume rules
            
    except KeyboardInterrupt:
        pass
        
    counter.finish()

if __name__ == "__main__":
    main()
