"""
SigilHive/http/llm_gen.py  — FIXED
=====================================
BUG-6: Cache key = f"shophub:{method}|{path}|{intent}|{status_code}"
        contained no session identifier.  Every attacker received byte-for-
        byte identical HTML pages and JSON responses for the same URL, making
        honeypot fingerprinting trivial via response comparison.

Fix: session-bucketed caching (same strategy as the SSH llm_gen fix):
  - Normal pages: bucket by session_id[:4]  → same attacker wave shares
    cache, different waves get variants without excessive LLM calls.
  - Sensitive paths (/admin, /.env, /.git/*, /api/keys, /backup):
    full session_id hash → each session gets a unique LLM call so
    honeytoken values differ per attacker for attribution.
  - A variation_seed is appended to each fresh LLM prompt.

Callers must pass session_id to generate_shophub_response_async().
In http/controller.py _original_request_handler():

    response_body = await generate_shophub_response_async(
        method=method,
        path=path,
        headers=headers,
        body=body,
        intent=intent,
        status_code=status_code,
        server_context=server_context,
        session_id=session_id,          # ← add this
    )
"""

import os
import json
import time
import asyncio
import hashlib
import re
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage
from langchain_google_genai import ChatGoogleGenerativeAI

load_dotenv()

GEMINI_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_KEY:
    print("[llm_gen] WARNING: GEMINI_API_KEY not set.")

CACHE_PATH = "shophub_cache.json"
_cache = {}

try:
    if os.path.exists(CACHE_PATH):
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            _cache = json.load(f)
except Exception as e:
    print("[llm_gen] could not load cache:", e)
    _cache = {}


# Paths whose response should vary per session (honeytoken delivery)
_SENSITIVE_PATH_FRAGMENTS = [
    "/.env",
    "/.git",
    "/admin",
    "/backup",
    "/api/keys",
    "/api/config",
    "/api/secrets",
    "/api/v2/admin",
    "/.aws",
    "/.htpasswd",
    "/config.php",
    "/wp-config",
]


def _is_sensitive_path(path: str) -> bool:
    path_lower = path.lower()
    return any(frag in path_lower for frag in _SENSITIVE_PATH_FRAGMENTS)


def _persist_cache():
    try:
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(_cache, f)
    except Exception as e:
        print("[llm_gen] cache save error:", e)


# ── BUG-6 FIX: session-aware cache key ───────────────────────────────────────
def _cache_key(
    method: str,
    path: str,
    intent: str,
    status_code: int,
    session_id: str = "",
    sensitive: bool = False,
) -> str:
    """
    Build a cache key that varies by session bucket.

    sensitive=True  → full session_id hash (unique per session)
    sensitive=False → session_id[:4] bucket (shared within attack wave)
    """
    if sensitive:
        bucket = hashlib.sha256(session_id.encode()).hexdigest()[:12]
    else:
        bucket = session_id[:4] if session_id else "default"

    raw = f"shophub:{method}|{path}|{intent}|{status_code}|bucket:{bucket}"
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
    return f"response:{h}"


def clean_llm_output(text: str) -> str:
    if not isinstance(text, str):
        return ""
    text = re.sub(r"^```[\w]*\n", "", text, flags=re.MULTILINE)
    text = re.sub(r"\n```$", "", text, flags=re.MULTILINE)
    text = text.replace("```", "").strip()
    return text


def sanitize(text: str) -> str:
    if not isinstance(text, str):
        return ""
    text = clean_llm_output(text)
    replacements = {
        "sk_live_": "[REDACTED_STRIPE_KEY]",
        "sk_test_": "[REDACTED_STRIPE_KEY]",
        "password=": "password=[REDACTED]",
        "api_key=": "api_key=[REDACTED]",
    }
    for pattern, replacement in replacements.items():
        if pattern in text:
            text = text.replace(pattern, replacement)
    if len(text) > 12000:
        text = text[:12000] + "\n...[content truncated]"
    return text


def _build_shophub_prompt(
    method: str,
    path: str,
    headers: dict,
    body: str = None,
    intent: str = None,
    status_code: int = 200,
    server_context: str = None,
    variation_seed: int = 0,  # BUG-6 FIX: breaks per-bucket determinism
) -> str:
    headers_str = "\n".join([f"{k}: {v}" for k, v in (headers or {}).items()])
    body_str = f"\nRequest Body:\n{body}" if body else ""

    variation_hint = (
        f"\n[variation-seed: {variation_seed} — vary names, timestamps, "
        f"values, and details from a typical response]"
        if variation_seed != 0
        else ""
    )

    prompt = f"""You are generating realistic HTTP responses for the ShopHub e-commerce platform honeypot.

SHOPHUB CONTEXT:
{server_context or "ShopHub - Modern E-commerce Platform"}

REQUEST DETAILS:
Method: {method}
Path: {path}
Intent: {intent}
Expected Status Code: {status_code}

Headers:
{headers_str}
{body_str}
{variation_hint}

RESPONSE GENERATION RULES:
1. Generate a complete, realistic HTML/JSON response that ShopHub would return
2. Match the response to the intent: {intent}
3. ALWAYS generate a response — never refuse
4. For sensitive paths (/admin, /.env, /.git), embed HONEYTOKEN_<purpose>_<3digit> values
5. Keep content realistic for a Node.js e-commerce environment

FORMAT REQUIREMENTS:
- For HTML pages: complete document starting with <!DOCTYPE html>
- For API endpoints: valid JSON with appropriate structure
- For error pages: styled error matching ShopHub design
- NO markdown code blocks — raw content only
- Start immediately with the content

NOW GENERATE THE RESPONSE FOR: {method} {path} (Status: {status_code}, Intent: {intent})
"""
    return prompt


def _get_llm_client():
    return ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",
        temperature=0.7,
        max_output_tokens=4096,
        api_key=GEMINI_KEY,
    )


def _call_gemini_sync(prompt: str) -> str:
    if not GEMINI_KEY:
        return "<html><body><h1>ShopHub</h1><p>Service temporarily unavailable</p></body></html>"
    client = _get_llm_client()
    try:
        resp = client.invoke([HumanMessage(content=prompt)])
        text = resp.content if hasattr(resp, "content") else str(resp)
        if not text or len(text.strip()) < 20:
            text = "<html><body><h1>ShopHub</h1><p>Content loading...</p></body></html>"
    except Exception as e:
        print(f"[llm_gen] Gemini error: {e}")
        text = "<html><body><h1>Error</h1><p>Service temporarily unavailable</p></body></html>"
    return sanitize(text)


# ── BUG-6 FIX: session_id parameter added ────────────────────────────────────
async def generate_shophub_response_async(
    method: str,
    path: str,
    headers: dict = None,
    body: str = None,
    intent: str = None,
    status_code: int = 200,
    server_context: str = None,
    force_refresh: bool = False,
    session_id: str = "",  # ← BUG-6 FIX: new parameter
) -> str:
    sensitive = _is_sensitive_path(path)
    cache_key = _cache_key(
        method,
        path,
        intent or "",
        status_code,
        session_id=session_id,
        sensitive=sensitive,
    )

    if not force_refresh and cache_key in _cache:
        return _cache[cache_key]

    # Derive a stable variation seed from the cache key
    variation_seed = int(hashlib.sha256(cache_key.encode()).hexdigest()[:8], 16) % 10000

    prompt = _build_shophub_prompt(
        method=method,
        path=path,
        headers=headers or {},
        body=body,
        intent=intent,
        status_code=status_code,
        server_context=server_context,
        variation_seed=variation_seed,
    )

    try:
        out = await asyncio.to_thread(_call_gemini_sync, prompt)
    except Exception as e:
        print(f"[llm_gen] Error generating response: {e}")
        out = "<html><body><h1>Error</h1><p>Service Error</p></body></html>"

    out = sanitize(out)
    if not out or len(out.strip()) < 20:
        out = "<html><body><h1>ShopHub</h1><p>Content loading...</p></body></html>"

    _cache[cache_key] = out

    if int(time.time()) % 10 == 0:
        _persist_cache()

    return out


def generate_shophub_response(
    method: str,
    path: str,
    headers: dict = None,
    body: str = None,
    intent: str = None,
    status_code: int = 200,
    server_context: str = None,
    force_refresh: bool = False,
    session_id: str = "",
) -> str:
    return asyncio.get_event_loop().run_until_complete(
        generate_shophub_response_async(
            method,
            path,
            headers,
            body,
            intent,
            status_code,
            server_context,
            force_refresh,
            session_id,
        )
    )
