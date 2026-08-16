"""Rule-based detection: fast, deterministic, fully explainable.

This is the first half of the hybrid engine. Rules catch known attack shapes
instantly and with zero training, but only the shapes we thought to encode --
which is exactly why the ML model runs alongside them.
"""

from typing import Tuple

from app.config import BRUTE_FAIL_RATE, BRUTE_MIN_REQ, DOS_REQ_COUNT
from app.models import Feature

RULE_NONE = "none"
RULE_DOS = "dos"
RULE_BRUTE_FORCE = "brute_force"


def apply_rules(feat: Feature) -> Tuple[bool, str]:
    """Evaluate one feature vector against the rule set.

    Returns (rule_flag, rule_type).
    """
    # Brute force is checked first: a high failure rate is a far more specific
    # signature than volume alone, so a high-volume credential attack should be
    # reported as brute_force rather than as a generic flood.
    if feat.fail_rate > BRUTE_FAIL_RATE and feat.req_count >= BRUTE_MIN_REQ:
        return True, RULE_BRUTE_FORCE

    if feat.req_count > DOS_REQ_COUNT:
        return True, RULE_DOS

    return False, RULE_NONE


def describe_rules() -> dict:
    """The active thresholds, surfaced on the dashboard and in /config."""
    return {
        "dos": f"req_count > {DOS_REQ_COUNT} in one window",
        "brute_force": (
            f"fail_rate > {BRUTE_FAIL_RATE} AND req_count >= {BRUTE_MIN_REQ}"
        ),
    }
