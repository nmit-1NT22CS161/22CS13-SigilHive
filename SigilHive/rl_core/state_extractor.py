import os
import json
from typing import Tuple, List, Dict
from .config import STATE_BUCKETS, PROTOCOL_SETTINGS


def extract_state(session_id: str, protocol: str) -> Tuple:
    """
    Extract current state for a session.

    Returns:
        State tuple: (commands_per_min, unique_cmds, duration, error_ratio, privesc)
        Each value is 0 (LOW), 1 (MED), or 2 (HIGH).
    """
    logs = _load_session_logs(session_id, protocol)

    if not logs:
        return (0, 0, 0, 0, 0)

    commands_per_min = _calculate_commands_per_minute(logs)
    unique_commands = _calculate_unique_commands(logs, protocol)
    duration = _calculate_session_duration(logs)
    error_ratio = _calculate_error_ratio(logs, protocol)
    privesc = _detect_privilege_escalation(logs, protocol)

    state = (
        _discretize(commands_per_min, STATE_BUCKETS["commands_per_minute"]),
        _discretize(unique_commands, STATE_BUCKETS["unique_commands"]),
        _discretize(duration, STATE_BUCKETS["session_duration"]),
        _discretize(error_ratio, STATE_BUCKETS["error_ratio"]),
        1 if privesc else 0,
    )
    return state


def _load_session_logs(session_id: str, protocol: str) -> List[Dict]:
    log_dir = f"storage/session_logs/{protocol}"
    log_path = os.path.join(log_dir, f"{session_id}.jsonl")

    if not os.path.exists(log_path):
        return []

    logs = []
    try:
        with open(log_path, "r") as f:
            for line in f:
                line = line.strip()
                if line:
                    logs.append(json.loads(line))
    except Exception as e:
        print(f"[StateExtractor] Error loading logs: {e}")
        return []

    return logs


# ── BUG-3 FIX ────────────────────────────────────────────────────────────────
def _calculate_commands_per_minute(logs: List[Dict]) -> float:
    """
    Calculate command/query/request rate in commands per minute.

    BUG-3 (original): when duration < 1 second, returned float(len(logs))
    which is the raw count, not a per-minute rate.  A 5-command burst in
    0.4 s should be ~750 cmd/min (HIGH bucket), not 5.0 (also HIGH, but
    by accident, and semantically wrong).

    Fix: always compute the rate; use max(duration, 1) to prevent
    division-by-zero while keeping the value meaningful.
    """
    if not logs:
        return 0.0

    timestamps = [log.get("timestamp", 0) for log in logs]
    if not timestamps:
        return 0.0

    duration_seconds = max(timestamps) - min(timestamps)

    # FIX: use max(duration_seconds, 1) — avoids the raw-count fallback
    # that caused sub-second bursts to be mis-measured.
    return (len(logs) / max(duration_seconds, 1)) * 60.0


# ── BUG-1 FIX ────────────────────────────────────────────────────────────────
def _calculate_unique_commands(logs: List[Dict], protocol: str) -> int:
    """
    Count unique commands / paths / query types across the session.

    BUG-1 (original): `return len(unique)` was indented one level too deep,
    sitting INSIDE the for-loop body.  The function always exited after
    processing the FIRST log entry, so the unique count was permanently
    stuck at 0 or 1 regardless of session length.  This froze the 'u'
    (unique commands) dimension of the state tuple, collapsing the 243-state
    space to at most 81 reachable states.

    Fix: dedent the return statement to be OUTSIDE the for-loop.
    """
    if not logs:
        return 0

    unique: set = set()

    for log in logs:
        input_data = log.get("input_data", "")

        if protocol == "ssh":
            cmd = input_data.split()[0] if input_data.split() else ""
            if cmd:
                unique.add(cmd)

        elif protocol == "http":
            parts = input_data.split()
            path = parts[1] if len(parts) > 1 else ""
            path = path.split("?")[0]  # strip query string
            if path:
                unique.add(path)

        elif protocol == "database":
            query_upper = input_data.upper().strip()
            query_type = query_upper.split()[0] if query_upper.split() else ""
            if query_type:
                unique.add(query_type)

    # ← FIX: this return is now OUTSIDE the for-loop
    return len(unique)


def _calculate_session_duration(logs: List[Dict]) -> float:
    """Return session duration in seconds."""
    if not logs:
        return 0.0
    timestamps = [log.get("timestamp", 0) for log in logs]
    if not timestamps:
        return 0.0
    return max(timestamps) - min(timestamps)


def _calculate_error_ratio(logs: List[Dict], protocol: str) -> float:
    """
    Calculate ratio of failed / error responses.

    Reads the 'success' key written by log_interaction().
    After BUG-2 is fixed in structured_logger.py, this field will
    reflect actual success/failure per interaction.
    """
    if not logs:
        return 0.0

    total = len(logs)
    errors = 0

    for log in logs:
        metadata = log.get("metadata", {})

        if protocol == "ssh":
            if not log.get("success", True):
                errors += 1

        elif protocol == "http":
            status_code = metadata.get("status_code", 200)
            if status_code >= 400:
                errors += 1

        elif protocol == "database":
            if not log.get("success", True):
                errors += 1

    return errors / total if total > 0 else 0.0


def _detect_privilege_escalation(logs: List[Dict], protocol: str) -> bool:
    """Detect privilege escalation indicators in the session logs."""
    if not logs:
        return False

    settings = PROTOCOL_SETTINGS.get(protocol, {})

    for log in logs:
        input_data = log.get("input_data", "").lower()
        metadata = log.get("metadata", {})

        if protocol == "ssh":
            for cmd in settings.get("privesc_commands", []):
                if cmd.lower() in input_data:
                    return True
            for f in settings.get("sensitive_files", []):
                if f.lower() in input_data:
                    return True

        elif protocol == "http":
            for path in settings.get("admin_paths", []):
                if path.lower() in input_data:
                    return True

        elif protocol == "database":
            if "mysql.user" in input_data or "grant" in input_data:
                return True
            for kw in settings.get("injection_keywords", []):
                if kw.lower() in input_data:
                    return True

    return False


def _discretize(value: float, thresholds: list) -> int:
    """Discretize continuous value into LOW (0) / MED (1) / HIGH (2)."""
    if value < thresholds[0]:
        return 0
    elif value < thresholds[1]:
        return 1
    else:
        return 2
