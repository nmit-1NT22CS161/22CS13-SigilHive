"""
SigilHive/database/llm_gen.py  — FIXED
=========================================
BUG-7: Cache key = f"query:{query}|intent:{intent}|ctx:{db_context}"
        contained no session identifier.  Two attackers running the same
        SQL query (e.g. SELECT * FROM admin_users LIMIT 5) against the
        same database state received identical result sets — including
        identical fake password hashes, API keys, and credit card numbers.
        This prevented honeytoken attribution and made the honeypot
        detectable via response comparison.

Fix: session-bucketed caching:
  - Normal queries: bucket by session_id[:4]
  - Sensitive tables (admin_users, api_keys, credit_cards, sessions,
    users, mysql.user): full session_id hash → unique result set per
    attacker session for reliable honeytoken attribution.

Callers must pass session_id to generate_db_response_async().
In database/controller.py _original_query_handler():

    llm_raw = await generate_db_response_async(
        query=query,
        intent=intent,
        db_context=db_context,
        session_id=session_id,   # ← add this
    )
"""

import os
import json
import time
import asyncio
import hashlib
import re
from typing import Optional
from dotenv import load_dotenv

from langchain_core.messages import HumanMessage, SystemMessage
from langchain_google_genai import ChatGoogleGenerativeAI

load_dotenv()

GEMINI_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_KEY:
    print("[llm_gen] WARNING: GEMINI_API_KEY not set")

CACHE_PATH = "shophub_db_cache.json"
_cache = {}

try:
    if os.path.exists(CACHE_PATH):
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            _cache = json.load(f)
except Exception as e:
    print(f"[llm_gen] cache load error: {e}")
    _cache = {}


def _persist_cache():
    try:
        tmp = CACHE_PATH + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(_cache, f, ensure_ascii=False, indent=2)
        os.replace(tmp, CACHE_PATH)
    except Exception as e:
        print(f"[llm_gen] cache save error: {e}")


# Tables whose query results must differ per session (for honeytoken attribution)
_SENSITIVE_TABLES = {
    "admin_users",
    "api_keys",
    "credit_cards",
    "sessions",
    "users",
    "user",
    "authentication_string",
    "backup_credentials",
    "session_tokens",
    "user_passwords",
}

_SENSITIVE_SYSTEM_PATTERNS = [
    "mysql.user",
    "information_schema",
    "authentication_string",
    "password_hash",
    "into outfile",
    "load_file",
]


def _is_sensitive_query(query: str) -> bool:
    q_lower = query.lower()
    # Check table name mentions
    for table in _SENSITIVE_TABLES:
        if table in q_lower:
            return True
    for pattern in _SENSITIVE_SYSTEM_PATTERNS:
        if pattern in q_lower:
            return True
    return False


# ── BUG-7 FIX: session-aware cache key ───────────────────────────────────────
def _cache_key(
    query: str,
    intent: str,
    db_context: str,
    session_id: str = "",
    sensitive: bool = False,
) -> str:
    if sensitive:
        bucket = hashlib.sha256(session_id.encode()).hexdigest()[:12]
    else:
        bucket = session_id[:4] if session_id else "default"

    raw = f"query:{query}|intent:{intent}|ctx:{db_context}|bucket:{bucket}"
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
    return f"db:{h}"


def sanitize(text: str) -> str:
    if not isinstance(text, str):
        return ""
    replacements = {
        "$2b$10$": "$2b$10$[REDACTED]",
        "txn_": "txn_[REDACTED]",
        "PAY-": "PAY-[REDACTED]",
    }
    out = text
    for pattern, replacement in replacements.items():
        if pattern in out:
            out = out.replace(pattern, replacement)
    if len(out) > 50000:
        out = out[:50000] + "\n...[truncated]"
    return out


def extract_json_from_response(text: str) -> Optional[dict]:
    if not isinstance(text, str) or not text.strip():
        return None

    text = text.strip()
    text_clean = re.sub(r"```json\s*", "", text)
    text_clean = re.sub(r"```\s*", "", text_clean).strip()

    try:
        data = json.loads(text_clean)
        if isinstance(data, dict) and (
            "columns" in data or "text" in data or "error" in data
        ):
            return data
    except json.JSONDecodeError:
        pass

    if "{" in text_clean:
        start = text_clean.find("{")
        brace_count = 0
        for i in range(start, len(text_clean)):
            if text_clean[i] == "{":
                brace_count += 1
            elif text_clean[i] == "}":
                brace_count -= 1
                if brace_count == 0:
                    try:
                        data = json.loads(text_clean[start : i + 1])
                        if isinstance(data, dict):
                            return data
                    except json.JSONDecodeError:
                        break

    if text_clean.strip().startswith("["):
        try:
            data = json.loads(text_clean)
            if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
                columns = list(data[0].keys())
                rows = [[row.get(col) for col in columns] for row in data]
                return {"columns": columns, "rows": rows}
        except json.JSONDecodeError:
            pass

    return None


def _build_prompt(
    query: str,
    intent: Optional[str] = None,
    db_context: Optional[str] = None,
    variation_seed: int = 0,  # BUG-7 FIX: breaks per-bucket determinism
) -> str:
    query_lower = query.lower().strip()
    is_select = any(kw in query_lower for kw in ["select", "show", "describe"])

    if is_select:
        format_instruction = """Output ONLY a JSON object in this EXACT format with NO other text:
{"columns": ["col1", "col2"], "rows": [[val1, val2], [val3, val4]]}

CRITICAL: Start with {, end with }, NO markdown, NO explanations."""
    else:
        format_instruction = """Output ONLY a status message:
For success: "Query OK, N row(s) affected"
For errors: "ERROR 1234 (SQLSTATE): message"
Just the status line, nothing else."""

    variation_hint = (
        f"\n[variation-seed: {variation_seed} — vary names, hashes, keys, "
        f"timestamps, and values from typical output while keeping format correct]"
        if variation_seed != 0
        else ""
    )

    prompt = f"""You are a MySQL 8.0 database simulator for ShopHub e-commerce platform.

DATABASE SCHEMA:
{db_context or "ShopHub E-commerce Database"}

QUERY TO EXECUTE:
{query}
{variation_hint}

{format_instruction}

DATA GENERATION RULES (for SELECT queries):
- Generate 5-20 realistic, varied rows
- Use realistic names, emails, addresses, products, prices
- Vary the data — don't repeat patterns
- Use timestamps from 2024-2025
- Sequential IDs starting from 1

SECURITY (always apply):
- Passwords: use HONEYTOKEN_HASH_<3digits> pattern (NOT real bcrypt)
- Credit cards: mask to last 4 digits (e.g., ****1234)
- API keys: HONEYTOKEN_KEY_<service>_<3digits>

Now generate the response:"""

    return prompt


def _get_llm_client():
    return ChatGoogleGenerativeAI(
        model="gemini-2.5-pro",
        temperature=0.2,
        max_output_tokens=8192,
        api_key=GEMINI_KEY,
    )


def _call_gemini_sync(prompt: str) -> str:
    client = _get_llm_client()
    try:
        is_select = any(kw in prompt.lower() for kw in ["select", "show", "describe"])
        if is_select:
            system_msg = SystemMessage(
                content="You must respond with ONLY valid JSON. No markdown, no explanations, "
                "just pure JSON starting with { and ending with }."
            )
            messages = [system_msg, HumanMessage(content=prompt)]
        else:
            messages = [HumanMessage(content=prompt)]

        resp = client.invoke(messages)
        content = resp.content if hasattr(resp, "content") else str(resp)
        if isinstance(content, list):
            content = " ".join(map(str, content))
        return content.strip()

    except Exception as e:
        print(f"[llm_gen] LLM call error: {e}")
        return f"ERROR 2013 (HY000): Lost connection to database server - {e}"


def _validate_and_fix_json(data: dict) -> dict:
    if not isinstance(data, dict):
        return {"text": str(data)}
    if "text" in data or "error" in data:
        return data
    if "columns" in data or "rows" in data:
        if "columns" not in data:
            data["columns"] = []
        if "rows" not in data:
            data["rows"] = []
        data["columns"] = [str(col) for col in data["columns"]]
        fixed_rows = []
        for row in data["rows"]:
            if isinstance(row, list):
                fixed_rows.append(row)
            elif isinstance(row, dict):
                fixed_rows.append([row.get(col) for col in data["columns"]])
        data["rows"] = fixed_rows
        return data
    return {"text": json.dumps(data)}


# ── BUG-7 FIX: session_id parameter added ────────────────────────────────────
async def generate_db_response_async(
    query: str,
    intent: Optional[str] = None,
    db_context: Optional[str] = None,
    force_refresh: bool = False,
    session_id: str = "",  # ← BUG-7 FIX: new parameter
) -> dict:
    """
    Generate database response using LLM (async).

    Returns dict with either:
      {"columns": [...], "rows": [...]} for SELECT/SHOW queries
      {"text": "..."}                   for DDL/DML queries
    """
    sensitive = _is_sensitive_query(query)
    cache_key = _cache_key(
        query,
        intent or "",
        db_context or "",
        session_id=session_id,
        sensitive=sensitive,
    )

    if not force_refresh and cache_key in _cache:
        cached = _cache[cache_key]
        if isinstance(cached, str):
            json_data = extract_json_from_response(cached)
            if json_data:
                return _validate_and_fix_json(json_data)
            return {"text": cached}
        return _validate_and_fix_json(cached)

    # Derive variation seed from cache key for stable but varied output
    variation_seed = int(hashlib.sha256(cache_key.encode()).hexdigest()[:8], 16) % 10000

    prompt = _build_prompt(query, intent, db_context, variation_seed=variation_seed)

    try:
        raw_response = await asyncio.to_thread(_call_gemini_sync, prompt)
    except Exception as e:
        print(f"[llm_gen] Error during LLM call: {e}")
        return {"text": f"ERROR 2013 (HY000): Lost connection to MySQL server - {e}"}

    raw_response = sanitize(raw_response)

    if raw_response.startswith("ERROR") or raw_response.startswith("Query OK"):
        result = {"text": raw_response}
    else:
        json_data = extract_json_from_response(raw_response)
        if json_data:
            result = _validate_and_fix_json(json_data)
        else:
            result = {"text": raw_response}

    _cache[cache_key] = result

    try:
        if int(time.time()) % 10 == 0:
            _persist_cache()
    except Exception:
        pass

    return result


def generate_db_response(
    query: str,
    intent: Optional[str] = None,
    db_context: Optional[str] = None,
    force_refresh: bool = False,
    session_id: str = "",
) -> dict:
    return asyncio.run(
        generate_db_response_async(query, intent, db_context, force_refresh, session_id)
    )
