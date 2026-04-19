import os
import json
import time
from typing import Dict, Any, Optional


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
        log_dir = f"storage/session_logs/{protocol}"
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
