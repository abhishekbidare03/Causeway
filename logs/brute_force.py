"""Brute-force attack simulator.

A single attacker IP hammers /login with wrong credentials, cycling through a
username list. The signature is a very high failure rate at moderate volume --
which is exactly what the brute-force rule looks for:

    fail_rate > 0.7  AND  req_count >= 10   (per 5-second window)

Volume is kept below the DoS threshold on purpose, so this attack is classified
as brute force rather than as a flood.

Run:  python logs/brute_force.py
"""

import os
import random
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from logs.common import Counter, make_event, new_session, require_api, send

ATTACKER_IP = "45.83.91.207"
TARGET_ENDPOINT = "/login"

# ~7 attempts/sec  ->  ~35 requests per 5s window (above BRUTE_MIN_REQ = 10,
# below DOS_REQ_COUNT = 50).
TARGET_RATE = 7.0

# Usernames the attacker is guessing against.
USERNAMES = [
    "admin", "administrator", "root", "alice", "bob", "test",
    "guest", "operator", "sysadmin", "backup", "oracle", "postgres",
]


def main() -> None:
    require_api("Brute-Force Attack Simulator")
    print(f"Attacker IP : {ATTACKER_IP}")
    print(f"Target      : {TARGET_ENDPOINT}")
    print(f"Rate        : ~{TARGET_RATE:.0f} login attempts/sec\n")
    print("Expect: rule_type = brute_force on the dashboard within ~5 seconds.\n")

    session = new_session()
    counter = Counter("brute force")
    base_delay = 1.0 / TARGET_RATE

    try:
        while True:
            # The occasional 200 keeps fail_rate realistic (~0.95) rather than
            # a suspiciously perfect 1.0.
            status = 200 if random.random() < 0.05 else 401

            event = make_event(
                ip=ATTACKER_IP,
                endpoint=TARGET_ENDPOINT,
                status=status,
                user=random.choice(USERNAMES),
                size=180 if status == 401 else 940,
                layer="iam",
            )
            counter.record(send(session, event))
            time.sleep(base_delay * random.uniform(0.8, 1.2))
    except KeyboardInterrupt:
        counter.finish()


if __name__ == "__main__":
    main()
