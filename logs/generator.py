"""Normal traffic simulator.

Produces realistic background traffic: a pool of client IPs browsing a mix of
endpoints, mostly successful, with jittered timing. Per-IP request volume stays
well below every detection threshold, so a clean baseline is what the dashboard
shows until an attack script is started.

Run:  python logs/generator.py
"""

import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logs.common import Counter, make_event, new_session, require_api, send

# Roughly how many events per second across all client IPs combined.
TARGET_RATE = 7.0

CLIENT_IPS = [
    "192.168.1.10", "192.168.1.14", "192.168.1.22", "192.168.1.35",
    "10.0.0.7", "10.0.0.19", "10.0.0.42", "10.0.0.88",
    "172.16.4.5", "172.16.4.31", "203.0.113.14", "203.0.113.77",
]

USERS = ["alice", "bob", "carol", "dave", "erin", "frank", "grace", None]

# (endpoint, layer, relative weight, typical response size)
ENDPOINTS = [
    ("/",                "app",     10, 4200),
    ("/home",            "app",      8, 5100),
    ("/api/products",    "app",      9, 8800),
    ("/api/orders",      "app",      5, 3400),
    ("/api/profile",     "app",      4, 1900),
    ("/search",          "app",      5, 6200),
    ("/checkout",        "app",      2, 2700),
    ("/login",           "iam",      3,  850),
    ("/static/app.js",   "network",  6, 15400),
    ("/health",          "system",   2,  120),
]

ENDPOINT_WEIGHTS = [e[2] for e in ENDPOINTS]


def pick_status(endpoint: str) -> int:
    """Mostly successful, with a realistic sprinkling of errors."""
    roll = random.random()
    if endpoint == "/login":
        # A few genuine mistyped passwords -- not enough to look like an attack.
        return 401 if roll < 0.12 else 200
    if roll < 0.90:
        return 200
    if roll < 0.95:
        return 304
    if roll < 0.98:
        return 404
    return 500


def main() -> None:
    require_api("Normal Traffic Generator")
    print(f"Simulating ~{TARGET_RATE:.0f} requests/sec across "
          f"{len(CLIENT_IPS)} client IPs.\n")

    session = new_session()
    counter = Counter("normal traffic")
    base_delay = 1.0 / TARGET_RATE

    try:
        while True:
            endpoint, layer, _weight, size = random.choices(
                ENDPOINTS, weights=ENDPOINT_WEIGHTS, k=1
            )[0]
            status = pick_status(endpoint)

            # Error responses still carry a body (an error page), just a small
            # one -- a real server never returns zero bytes.
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
            )
            counter.record(send(session, event))

            # Jitter so traffic looks organic rather than metronomic.
            time.sleep(base_delay * random.uniform(0.5, 1.5))
    except KeyboardInterrupt:
        counter.finish()


if __name__ == "__main__":
    main()
