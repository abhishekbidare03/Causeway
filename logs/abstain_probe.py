"""Send various traffic bursts to find the Abstention Gate."""

import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from logs.common import Counter, make_event, new_session, require_api, send

def main() -> None:
    session = new_session()
    
    # 9 requests, 100% fail. Should be very suspicious (rule needs 10)
    for _ in range(9):
        event = make_event("10.0.0.1", "/login", 401, "admin", 200, "app")
        send(session, event)
    print("Sent 9 failed requests")
    
    # Large volume of data, but not enough requests for DoS rule (needs 50)
    # We will send 49 requests, each with a massive payload size.
    for _ in range(49):
        event = make_event("10.0.0.2", "/api/data", 200, "user", 50000, "app")
        send(session, event)
    print("Sent 49 heavy requests")

if __name__ == "__main__":
    main()
