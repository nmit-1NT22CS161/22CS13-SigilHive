import os
import json
import hashlib
import time
import asyncio
import re
from dotenv import load_dotenv
from langchain_core.messages import HumanMessage
from langchain_google_genai import ChatGoogleGenerativeAI

load_dotenv()

GEMINI_KEY = os.getenv("GEMINI_API_KEY")
if not GEMINI_KEY:
    print("[llm_gen] WARNING: GEMINI_API_KEY not set.")

CACHE_PATH = "ssh_llm_cache.json"
_cache = {}

try:
    if os.path.exists(CACHE_PATH):
        with open(CACHE_PATH, "r", encoding="utf-8") as f:
            _cache = json.load(f)
except Exception as e:
    print("[llm_gen] could not load cache:", e)
    _cache = {}


# Paths whose content should vary between sessions (honeytokens)
_SENSITIVE_PATH_FRAGMENTS = [
    ".env",
    "id_rsa",
    "shadow",
    "passwd",
    "credentials",
    "secrets",
    ".aws",
    "api_key",
    "token",
]


def _is_sensitive(command: str, filename_hint: str = None) -> bool:
    """Return True if this request involves sensitive honeytoken content."""
    targets = [command or "", filename_hint or ""]
    combined = " ".join(targets).lower()
    return any(frag in combined for frag in _SENSITIVE_PATH_FRAGMENTS)


def _persist_cache():
    try:
        with open(CACHE_PATH, "w", encoding="utf-8") as f:
            json.dump(_cache, f)
    except Exception as e:
        print("[llm_gen] cache save error:", e)


# FIX 6: cache key now includes session_id bucket so each session
# gets its own variants, and sensitive paths bypass the cache entirely.
def _cache_key(
    prefix: str, key: str, session_id: str = "", sensitive: bool = False
) -> str:
    if sensitive:
        # Never share cache across sessions for sensitive content
        bucket = hashlib.sha256(session_id.encode()).hexdigest()[:8]
    else:
        # Use a coarser bucket (first 4 chars of session_id) so similar
        # sessions within the same "wave" share responses but different
        # attackers don't.
        bucket = session_id[:4] if session_id else "default"

    raw = f"{key}|bucket:{bucket}"
    h = hashlib.sha256(raw.encode("utf-8")).hexdigest()[:24]
    return f"{prefix}:{h}"


_BANNED_SUBSTRS = [
    "rm -rf",
    "dd if=",
    "mkfs",
    ":(){:|:&};:",
    "curl http://malicious",
    "wget http://malicious",
    "nc -e",
    "ncat -e",
    "sshpass",
    "metasploit",
    "chmod 777",
    "chmod 666",
    "PRIVATE KEY-----",
    "BEGIN RSA PRIVATE KEY",
    "BEGIN OPENSSH PRIVATE KEY",
    "api_key=",
    "API_KEY=",
    "SECRET_KEY=",
    "password=",
    "PASSWORD=",
    "sk_live_",
    "sk_test_",
]


def sanitize(text: str) -> str:
    if not isinstance(text, str):
        return ""
    out = re.sub(r"```[a-zA-Z]*\n?", "", text)
    out = re.sub(r"\n?```", "", out)
    out = re.sub(r"^#+\s+", "", out, flags=re.MULTILINE)
    out = out.replace("```", "")
    for b in _BANNED_SUBSTRS:
        out = out.replace(b, "[REDACTED]")
    if len(out) > 8000:
        out = out[:8000] + "\n...[truncated]"
    return out.strip()


def _build_prompt(
    command: str,
    filename_hint: str = None,
    persona: str = None,
    context: dict = None,
    variation_seed: int = 0,  # FIX 6: unique seed per fresh generation
) -> str:
    persona_line = (
        f"You are simulating terminal output for a {persona} system."
        if persona
        else "You are simulating terminal output for a Linux server."
    )
    context_info = ""
    if context:
        current_dir = context.get("current_directory", "~")
        dir_desc = context.get("directory_description", "")
        dir_contents = context.get("directory_contents", [])
        app_name = context.get("application", "")
        tech_stack = context.get("application_tech", "")
        context_info = (
            f"\nCURRENT CONTEXT:\n"
            f"- Current Directory: {current_dir}\n"
            f"- Directory Description: {dir_desc}\n"
            f"- Directory Contains: {', '.join(dir_contents) if dir_contents else 'empty'}\n"
            f"- Application: {app_name}\n"
            f"- Tech Stack: {tech_stack}\n"
        )
    file_info = f"Target file: {filename_hint}" if filename_hint else ""

    # FIX 6: append variation seed so LLM produces different output
    # for different session buckets (varies names, timestamps, values)
    variation_hint = (
        f"\n[variation-seed: {variation_seed} — vary names, timestamps, "
        f"and values slightly from typical output]"
        if variation_seed != 0
        else ""
    )

    prompt = f"""{persona_line}
{context_info}
CRITICAL SAFETY RULES:
1) Generate ONLY realistic terminal output — command results, file contents, or directory listings
2) NEVER include real passwords, private keys, or real API keys
3) For tokens/keys, use placeholder patterns like HONEYTOKEN_<purpose>_<3-digit-number>
4) Make outputs contextually appropriate for the current directory and application
5) Keep outputs realistic for a Node.js e-commerce platform environment

OUTPUT FORMAT:
- Output RAW TERMINAL TEXT ONLY — no markdown code fences, no explanations
- Output exactly what would appear in a real terminal

Command to simulate: `{command}`
{file_info}{variation_hint}

Generate ONLY the terminal output — no explanations, no markdown.
"""
    return prompt


def _get_llm_client():
    return ChatGoogleGenerativeAI(
        model="gemini-2.5-flash",
        temperature=0.7,
        max_output_tokens=2048,
        api_key=GEMINI_KEY,
    )


def _call_gemini_sync(prompt: str) -> str:
    if not GEMINI_KEY:
        return "# GEMINI_API_KEY not set — simulated placeholder output"
    client = _get_llm_client()
    try:
        resp = client.invoke([HumanMessage(content=prompt)])
        text = resp.content if hasattr(resp, "content") else str(resp)
    except Exception as e:
        print(f"[llm_gen] Gemini API error: {e}")
        text = "# (LLM unavailable)"
    return sanitize(text)


async def generate_response_for_command_async(
    command: str,
    filename_hint: str = None,
    persona: str = None,
    context: dict = None,
    force_refresh: bool = False,
    session_id: str = "",  # FIX 6: accept session_id for bucketed caching
) -> str:
    current_dir = context.get("current_directory", "~") if context else "~"
    sensitive = _is_sensitive(command, filename_hint)
    key_raw = f"cmd:{command}|dir:{current_dir}|file:{filename_hint or ''}"
    cache_key = _cache_key("resp", key_raw, session_id=session_id, sensitive=sensitive)

    if not force_refresh and cache_key in _cache:
        return _cache[cache_key]

    # FIX 6: use a stable but varied seed so each new bucket gets
    # slightly different output (different user names, timestamps, etc.)
    variation_seed = int(hashlib.sha256(cache_key.encode()).hexdigest()[:8], 16) % 10000

    prompt = _build_prompt(
        command=command,
        filename_hint=filename_hint,
        persona=persona,
        context=context,
        variation_seed=variation_seed,
    )

    try:
        out = await asyncio.to_thread(_call_gemini_sync, prompt)
    except Exception:
        out = f"bash: {command.split()[0]}: command not found"

    out = sanitize(out)
    _cache[cache_key] = out

    if int(time.time()) % 10 == 0:
        _persist_cache()

    return out


# Synchronous wrapper — also propagates session_id
def generate_response_for_command(
    command: str,
    filename_hint: str = None,
    persona: str = None,
    context: dict = None,
    force_refresh: bool = False,
    session_id: str = "",
) -> str:
    return asyncio.get_event_loop().run_until_complete(
        generate_response_for_command_async(
            command, filename_hint, persona, context, force_refresh, session_id
        )
    )
