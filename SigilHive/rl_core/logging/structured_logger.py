import os
import json
import time
from typing import Dict, Any, Optional
from ..config import LOGGING_CONFIG


def summarize_response_quality(
    response_text: Any,
    *,
    action: str,
    protocol: str,
    suspicious: bool = False,
    success: bool = True,
    status_code: Optional[int] = None,
    disconnect: bool = False,
) -> Dict[str, Any]:
    """Generate lightweight response-quality features for RL shaping."""
    text = str(response_text or "")
    lower = text.lower()
    honeytoken_hits = lower.count("honeytoken")
    deception_hits = sum(
        token in lower
        for token in [
            "password",
            "secret",
            "api_key",
            "access_key",
            "admin dashboard",
            "id_rsa",
            "nopasswd",
            "backup.sql",
            "mysql.user",
        ]
    )
    empty_response = len(text.strip()) == 0
    quality_score = 0.0

    if success:
        quality_score += 1.0
    if not empty_response:
        quality_score += min(len(text) / 240.0, 4.0)
    quality_score += honeytoken_hits * 2.5
    quality_score += deception_hits * 1.25

    if suspicious:
        if honeytoken_hits or deception_hits:
            quality_score += 2.0
        elif action in {"DECEPTIVE_RESOURCE", "FAKE_VULNERABILITY"}:
            quality_score -= 1.0
    else:
        if action in {"DECEPTIVE_RESOURCE", "FAKE_VULNERABILITY"} and (honeytoken_hits or deception_hits):
            quality_score -= 1.5

    if empty_response:
        quality_score -= 4.0
    if disconnect:
        quality_score -= 2.0
    if status_code is not None and status_code >= 400 and suspicious:
        quality_score -= 1.0

    return {
        "response_action": action,
        "response_length": len(text),
        "honeytoken_hits": honeytoken_hits,
        "deception_hits": deception_hits,
        "empty_response": empty_response,
        "disconnect": disconnect,
        "quality_score": round(quality_score, 3),
        "protocol": protocol,
    }


def log_interaction(
    session_id: str,
    protocol: str,
    input_data: str,
    metadata: Optional[Dict[str, Any]] = None,
    success: bool = True,  # ← BUG-2 FIX: was always hardcoded True
) -> None:
    """
    Log an interaction event for RL training.

    Args:
        session_id: Unique session identifier.
        protocol:   Protocol type ("ssh", "http", or "database").
        input_data: The raw input/command/request.
        metadata:   Additional context (intent, status_code, etc.).
        success:    Whether the interaction represented a successful
                    (from the attacker's perspective) operation.
                    Pass False for: command-not-found, HTTP 4xx/5xx,
                    SQL ERROR responses, failed auth, etc.
    """
    try:
        log_dir = os.path.join(LOGGING_CONFIG["session_log_dir"], protocol)
        os.makedirs(log_dir, exist_ok=True)

        log_entry = {
            "timestamp": time.time(),
            "input_data": input_data,
            "success": success,
            "metadata": metadata or {},
        }

        log_file = f"{log_dir}/{session_id}.jsonl"
        with open(log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")

    except Exception as e:
        print(f"[StructuredLogger] Error logging interaction: {e}", flush=True)
