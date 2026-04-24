"""
Reward calculation module for RL honeypot system.

Computes reward signals based on state transitions to guide
the Q-learning agent toward optimal deception strategies.
"""

import json
import os
from typing import Optional, Tuple
from .config import LOGGING_CONFIG, REWARD_CONFIG


def calculate_reward(
    prev_state: Tuple,
    curr_state: Tuple,
    protocol: str,
    terminal: bool = False,
    session_id: Optional[str] = None,
) -> float:
    """
    Calculate reward for state transition.

    Reward = engagement from state transition + response quality shaping.
    """
    prev_rate, prev_unique, prev_duration, prev_errors, prev_privesc, prev_suspicious, prev_quality = _normalize_state(prev_state)
    curr_rate, curr_unique, curr_duration, curr_errors, curr_privesc, curr_suspicious, curr_quality = _normalize_state(curr_state)

    alpha = REWARD_CONFIG["alpha"]
    beta = REWARD_CONFIG["beta"]
    gamma1 = REWARD_CONFIG["gamma1"]
    gamma2 = REWARD_CONFIG["gamma2"]
    engagement_step = REWARD_CONFIG.get("engagement_step", 1.0)
    quality_weight = REWARD_CONFIG.get("quality_weight", 1.0)

    delta_duration = curr_duration - prev_duration
    delta_unique = curr_unique - prev_unique
    detection = 1 if _detect_honeypot_awareness(prev_state, curr_state) else 0
    termination = (
        1 if terminal and _detect_early_termination(prev_state, curr_state) else 0
    )

    reward = (
        alpha * _duration_bucket_to_seconds(delta_duration)
        + beta * delta_unique
        - gamma1 * detection
        - gamma2 * termination
    )
    reward += quality_weight * (curr_quality - prev_quality)

    if (
        not terminal
        and curr_rate > 0
        and (delta_unique > 0 or delta_duration > 0 or curr_privesc > prev_privesc)
        and not detection
    ):
        reward += engagement_step

    reward += _protocol_specific_bonus(prev_state, curr_state, protocol)
    reward += _response_quality_adjustment(protocol, session_id, terminal)

    return reward


def _normalize_state(state: Tuple) -> Tuple[int, int, int, int, int, int, int]:
    if len(state) >= 7:
        return tuple(int(x) for x in state[:7])
    if len(state) == 5:
        rate, unique, duration, errors, privesc = state
        return (int(rate), int(unique), int(duration), int(errors), int(privesc), 0, 0)

    padded = list(state)[:7]
    while len(padded) < 7:
        padded.append(0)
    return tuple(int(x) for x in padded)


def _duration_bucket_to_seconds(delta_bucket: int) -> float:
    if delta_bucket == 0:
        return 0.0
    if delta_bucket == 1:
        return 150.0
    if delta_bucket == 2:
        return 420.0
    if delta_bucket == -1:
        return -150.0
    if delta_bucket == -2:
        return -420.0
    return 0.0


def _detect_honeypot_awareness(prev_state: Tuple, curr_state: Tuple) -> bool:
    prev_rate, prev_unique, prev_duration, prev_errors, prev_privesc, prev_suspicious, prev_quality = _normalize_state(prev_state)
    curr_rate, curr_unique, curr_duration, curr_errors, curr_privesc, curr_suspicious, curr_quality = _normalize_state(curr_state)

    if curr_errors == 2 and prev_errors < 2:
        return True
    if curr_errors >= 1 and curr_duration == 0:
        return True
    if prev_rate == 2 and curr_rate == 0:
        return True
    if curr_suspicious and curr_quality == 0 and curr_errors >= 1:
        return True
    return False


def _detect_early_termination(prev_state: Tuple, curr_state: Tuple) -> bool:
    prev_rate, prev_unique, prev_duration, prev_errors, prev_privesc, prev_suspicious, prev_quality = _normalize_state(prev_state)
    curr_rate, curr_unique, curr_duration, curr_errors, curr_privesc, curr_suspicious, curr_quality = _normalize_state(curr_state)

    if curr_duration == 0 and curr_unique <= 2:
        return True
    if prev_rate > 0 and curr_rate == 0 and curr_unique < 3:
        return True
    return False


def _protocol_specific_bonus(
    prev_state: Tuple, curr_state: Tuple, protocol: str
) -> float:
    prev_rate, prev_unique, prev_duration, prev_errors, prev_privesc, prev_suspicious, prev_quality = _normalize_state(prev_state)
    curr_rate, curr_unique, curr_duration, curr_errors, curr_privesc, curr_suspicious, curr_quality = _normalize_state(curr_state)

    bonus = 0.0

    if protocol == "ssh":
        if curr_privesc and not prev_privesc:
            bonus += REWARD_CONFIG["ssh_privesc_bonus"]
        if curr_rate >= 1 and curr_duration >= 1:
            bonus += REWARD_CONFIG["ssh_file_access_bonus"]
        if curr_unique >= 2 and curr_duration >= 2:
            bonus += REWARD_CONFIG["ssh_persistence_bonus"]

    elif protocol == "http":
        if curr_unique - prev_unique >= 1:
            bonus += REWARD_CONFIG["http_path_diversity_bonus"]
        if curr_privesc and not prev_privesc:
            bonus += REWARD_CONFIG["http_admin_access_bonus"]
        if curr_rate >= 1 and curr_unique >= 2:
            bonus += REWARD_CONFIG["http_honeytoken_bonus"]

    elif protocol == "database":
        if curr_unique - prev_unique >= 1:
            bonus += REWARD_CONFIG["db_table_enum_bonus"]
        if curr_privesc and not prev_privesc:
            bonus += REWARD_CONFIG["db_injection_attempt_bonus"]
        if curr_rate >= 1 and curr_unique >= 2 and curr_duration >= 1:
            bonus += REWARD_CONFIG["db_honeytoken_bonus"]

    return bonus


def _response_quality_adjustment(
    protocol: str,
    session_id: Optional[str],
    terminal: bool,
) -> float:
    if not session_id:
        return 0.0

    metadata = _load_latest_log_metadata(session_id, protocol)
    if not metadata:
        return 0.0

    reward = 0.0
    action = metadata.get("response_action", "BASELINE")
    suspicious = bool(metadata.get("suspicious"))
    honeytoken_hits = int(metadata.get("honeytoken_hits", 0) or 0)
    deception_hits = int(metadata.get("deception_hits", 0) or 0)
    empty_response = bool(metadata.get("empty_response"))
    disconnect = bool(metadata.get("disconnect"))

    reward += float(metadata.get("quality_score", 0.0)) * REWARD_CONFIG.get("quality_weight", 1.0)
    reward += honeytoken_hits * REWARD_CONFIG.get("honeytoken_reward", 1.0)
    reward += deception_hits * REWARD_CONFIG.get("deception_reward", 1.0)

    if empty_response:
        reward -= REWARD_CONFIG.get("empty_response_penalty", 0.0)

    if suspicious:
        if action in {"DECEPTIVE_RESOURCE", "FAKE_VULNERABILITY", "MISLEADING_SUCCESS"} and (honeytoken_hits or deception_hits):
            reward += 2.0
        elif action in {"DECEPTIVE_RESOURCE", "FAKE_VULNERABILITY"}:
            reward -= REWARD_CONFIG.get("suspicious_miss_penalty", 0.0)
    elif action in {"DECEPTIVE_RESOURCE", "FAKE_VULNERABILITY"} and (honeytoken_hits or deception_hits):
        reward -= REWARD_CONFIG.get("benign_deception_penalty", 0.0)

    if terminal and disconnect:
        reward -= REWARD_CONFIG.get("disconnect_penalty", 0.0)

    return reward


def _load_latest_log_metadata(session_id: str, protocol: str) -> dict:
    log_dir = os.path.join(LOGGING_CONFIG["session_log_dir"], protocol)
    log_path = os.path.join(log_dir, f"{session_id}.jsonl")
    if not os.path.exists(log_path):
        return {}

    try:
        with open(log_path, "r", encoding="utf-8") as f:
            lines = [line.strip() for line in f if line.strip()]
        if not lines:
            return {}
        return json.loads(lines[-1]).get("metadata", {})
    except Exception:
        return {}


if __name__ == "__main__":
    print("Testing reward calculation...\n")

    prev = (1, 2, 1, 0, 0, 0, 0)
    curr = (1, 3, 2, 0, 1, 1, 2)
    reward = calculate_reward(prev, curr, "ssh")
    print(f"Positive reward example: {reward:.2f}")

    prev = (1, 1, 0, 0, 0, 0, 1)
    curr = (0, 1, 0, 2, 0, 1, 0)
    reward = calculate_reward(prev, curr, "ssh", terminal=True)
    print(f"Negative reward example: {reward:.2f}")
