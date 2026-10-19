"""Authentication policy layer for false-positive reduction.

Evaluates AuthFeatures against the baseline store to distinguish benign activity
(e.g., stale cached passwords, single-user slow retries) from genuine attacks
(e.g., multi-source campaigns, high-diversity username sprays, rapid bursts, compromised logins).

Guarantees:
- Rank-only-lowers: Decision tiers are ordered autonomous (2) > soft_contain (1) > escalate (0).
  Policy rules can only downgrade or leave unchanged the gate decision, never elevate it.
- Fail-closed: On any exception or unhandled state, the policy falls back to "escalate".
- NullBaseline: When no baseline is provided, NullBaseline is used so existing tests
  and callers behave unchanged (all is_known_pair checks return False).
"""

import logging
from datetime import datetime
from typing import Any, Optional

from ai_engine.gate.auth_features import AuthFeatures, compute_auth_features
from ai_engine.schemas.models import IncidentState

logger = logging.getLogger("ai_engine.policy")

DECISION_RANK = {
    "escalate": 0,
    "soft_contain": 1,
    "autonomous": 2,
}

RANK_TO_DECISION = {rank: dec for dec, rank in DECISION_RANK.items()}


class NullBaseline:
    """Null-object baseline: never recognizes any pair as known."""

    def is_known_pair(
        self, username: Optional[str], source_ip: str, now: Optional[datetime] = None
    ) -> bool:
        return False


def _lower_decision(current: Optional[str], target: str) -> str:
    """Apply rank-only-lowers guarantee: return min(rank(current), rank(target))."""
    current_rank = DECISION_RANK.get(current, 0)
    target_rank = DECISION_RANK.get(target, 0)
    new_rank = min(current_rank, target_rank)
    return RANK_TO_DECISION.get(new_rank, "escalate")


def apply_auth_policy(
    state: IncidentState,
    baseline: Any = None,
    now: Optional[datetime] = None,
    features: Optional[AuthFeatures] = None,
) -> IncidentState:
    """Apply authentication policy rules to update state.final_decision.

    Rules:
    - R0: No auth failure events -> maintain gate decision.
    - R4: Success after failure (credential compromise / penetration)
          -> maintain gate decision (never downgrade). Runs FIRST before R1.
    - R1: Multi-source incident (source_count > 1) -> maintain gate decision (no downgrade).
    - R2: High-diversity username spray (distinct_usernames >= 3 or invalid_user_ratio > 0.5)
          -> maintain gate decision (no downgrade).
    - R3: Stale credentials / Known pair (known_pair is True, distinct_usernames == 1,
          median_gap_seconds >= 30.0s) -> downgrade to escalate for human review.
    - R5: Fast burst from unknown pair (median_gap_seconds < 5.0s, not known_pair)
          -> maintain gate decision (no downgrade).
    - Single-source cap: if source_count == 1 and none of R2/R3/R4 matched, cap via
          _lower_decision(state.final_decision, "soft_contain") (single-source auth
          evidence alone should never reach autonomous).

    Default: maintain gate decision.
    Rank-only-lowers guarantee: policy can never escalate permissions/autonomy.
    Fail-closed guarantee: any exception falls back to final_decision="escalate".
    """
    try:
        if state.final_decision is None:
            state.final_decision = "escalate"
            return state

        if baseline is None:
            baseline = NullBaseline()

        if features is None:
            features = compute_auth_features(state.events, baseline=baseline, now=now)

        # R0: No auth failure events in the incident
        if features.failure_count == 0:
            logger.debug("[R0] No auth failure events; maintaining decision: %s", state.final_decision)
            return state

        # R4: Success after failure (runs FIRST before R1; potential credential compromise)
        if features.success_after_failure:
            logger.info(
                "[R4] Success after failure detected; maintaining decision: %s",
                state.final_decision,
            )
            return state

        # R1: Multi-source attack (e.g. WAF + Wazuh, or FlowLog + Wazuh)
        if features.source_count > 1:
            logger.info(
                "[R1] Multi-source incident (sources=%d); maintaining decision: %s",
                features.source_count,
                state.final_decision,
            )
            return state

        # R2: High diversity username spray or mostly invalid users
        if features.distinct_usernames >= 3 or (
            features.invalid_user_ratio is not None and features.invalid_user_ratio > 0.5
        ):
            logger.info(
                "[R2] High-diversity spray attack (distinct_users=%d, invalid_ratio=%s); maintaining decision: %s",
                features.distinct_usernames,
                features.invalid_user_ratio,
                state.final_decision,
            )
            return state

        # R3: Stale credentials / Known pair (slow retry of single user) -> escalate for human review
        if (
            features.known_pair is True
            and features.distinct_usernames == 1
            and features.median_gap_seconds is not None
            and features.median_gap_seconds >= 30.0
        ):
            target = "escalate"
            new_decision = _lower_decision(state.final_decision, target)
            logger.info(
                "[R3] Stale credentials on known pair (median_gap=%.1fs); lowering %s -> %s",
                features.median_gap_seconds,
                state.final_decision,
                new_decision,
            )
            state.final_decision = new_decision
            return state

        # R5: Fast burst attack from unknown pair
        if (
            features.median_gap_seconds is not None
            and features.median_gap_seconds < 5.0
            and not features.known_pair
        ):
            logger.info(
                "[R5] Fast burst attack from unknown pair (median_gap=%.1fs); maintaining decision: %s",
                features.median_gap_seconds,
                state.final_decision,
            )
            return state

        # Single-source cap: single-source auth evidence alone should never reach autonomous
        if features.source_count == 1:
            new_decision = _lower_decision(state.final_decision, "soft_contain")
            logger.info(
                "[Single-Source Cap] Capping single-source auth evidence %s -> %s",
                state.final_decision,
                new_decision,
            )
            state.final_decision = new_decision
            return state

        # Default: maintain gate decision
        return state

    except Exception as exc:
        logger.error("Exception in apply_auth_policy (%s); failing closed to escalate", exc)
        state.final_decision = "escalate"
        return state
