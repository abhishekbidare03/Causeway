"""Denial-of-Service attack simulator.

A single attacker IP floods one endpoint as fast as it can. A small thread pool
is used because one synchronous request at a time cannot reach the volume
needed to make the dashboard spike convincingly.

The signature is sheer volume from one source:

    req_count > 50   (per 5-second window)

At the default rate a window contains roughly 800-1200 requests from the
attacker, versus 2-4 for a normal client.

Run:  python logs/dos_attack.py
"""

import os
import sys
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logs.common import Counter, make_event, new_session, require_api, send

ATTACKER_IP = "185.220.101.44"
TARGET_ENDPOINT = "/api/orders"

NUM_THREADS = 8
# Combined ceiling across all threads. Set to 0 for "as fast as possible".
TARGET_RATE = 200.0

_stop = threading.Event()


def worker(counter: Counter, per_thread_delay: float) -> None:
    session = new_session()
    while not _stop.is_set():
        event = make_event(
            ip=ATTACKER_IP,
            endpoint=TARGET_ENDPOINT,
            status=200,
            user=None,
            size=310,
            layer="network",
        )
        counter.record(send(session, event))
        if per_thread_delay > 0:
            time.sleep(per_thread_delay)


def main() -> None:
    require_api("DoS Attack Simulator")
    print(f"Attacker IP : {ATTACKER_IP}")
    print(f"Target      : {TARGET_ENDPOINT}")
    print(f"Threads     : {NUM_THREADS}")
    print(f"Rate        : ~{TARGET_RATE:.0f} requests/sec\n")
    print("Expect: requests/sec chart spikes and rule_type = dos within ~5 seconds.\n")

    counter = Counter("DoS flood")
    per_thread_delay = (NUM_THREADS / TARGET_RATE) if TARGET_RATE > 0 else 0.0

    threads = [
        threading.Thread(target=worker, args=(counter, per_thread_delay), daemon=True)
        for _ in range(NUM_THREADS)
    ]
    for t in threads:
        t.start()

    try:
        while True:
            time.sleep(0.2)
    except KeyboardInterrupt:
        _stop.set()
        for t in threads:
            t.join(timeout=2)
        counter.finish()


if __name__ == "__main__":
    main()
