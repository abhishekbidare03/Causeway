"""Shared helpers for the log generator / attack simulator scripts."""

import sys
import threading
import time
from datetime import datetime, timezone

import requests

API_URL = "http://127.0.0.1:8000"
LOGS_ENDPOINT = f"{API_URL}/logs"


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_event(ip, endpoint, status, user=None, size=None, layer="app"):
    """Build a normalized log event payload."""
    return {
        "timestamp": now_iso(),
        "ip": ip,
        "user": user,
        "endpoint": endpoint,
        "status": status,
        "bytes": size if size is not None else 0,
        "layer": layer,
    }


def new_session() -> requests.Session:
    """A keep-alive HTTP session (much faster than one connection per POST)."""
    session = requests.Session()
    adapter = requests.adapters.HTTPAdapter(pool_connections=16, pool_maxsize=16)
    session.mount("http://", adapter)
    return session


def send(session: requests.Session, event: dict) -> bool:
    """POST one event to the ingestion API. Returns True on success."""
    try:
        resp = session.post(LOGS_ENDPOINT, json=event, timeout=5)
        return resp.status_code == 200
    except requests.RequestException:
        return False


def wait_for_api(timeout: float = 15.0) -> bool:
    """Block until the API answers /health, so scripts can be started early."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            if requests.get(f"{API_URL}/health", timeout=2).status_code == 200:
                return True
        except requests.RequestException:
            pass
        time.sleep(0.5)
    return False


class Counter:
    """Thread-safe send counter with a one-line live progress display."""

    def __init__(self, label: str):
        self.label = label
        self.sent = 0
        self.failed = 0
        self.start = time.time()
        self._lock = threading.Lock()
        self._last_print = 0.0

    def record(self, ok: bool) -> None:
        with self._lock:
            if ok:
                self.sent += 1
            else:
                self.failed += 1
            now = time.time()
            if now - self._last_print >= 0.5:
                self._last_print = now
                self._print()

    def _print(self) -> None:
        elapsed = max(time.time() - self.start, 1e-6)
        rate = self.sent / elapsed
        sys.stdout.write(
            f"\r  {self.label}: {self.sent} events sent "
            f"| {rate:6.1f} events/sec | {self.failed} failed   "
        )
        sys.stdout.flush()

    def finish(self) -> None:
        self._print()
        elapsed = time.time() - self.start
        print(f"\n\nStopped. {self.sent} events in {elapsed:.1f}s "
              f"({self.sent / max(elapsed, 1e-6):.1f}/sec average).")


def require_api(script_name: str) -> None:
    """Exit with a clear message if the FastAPI server is not running."""
    print(f"\n=== {script_name} ===")
    print(f"Connecting to {API_URL} ...")
    if not wait_for_api():
        print(
            "\nERROR: could not reach the ingestion API.\n"
            "Start the server first, in another terminal:\n"
            "    uvicorn app.main:app --reload\n"
        )
        sys.exit(1)
    print("Connected. Press Ctrl+C to stop.\n")
