import argparse
import asyncio
import contextlib
import hashlib
import http.client
import importlib
import json
import math
import os
import pickle
import random
import shutil
import ssl
import subprocess
import sys
import tempfile
import time
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean
from typing import Any, Dict, List, Optional

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


DEFAULT_HTTP_PROBES = [
    "/",
    "/admin",
    "/.env",
    "/.git/config",
    "/backup/database_backup.sql",
    "/api/config",
]

DEFAULT_SSH_PROBES = [
    "whoami",
    "pwd",
    "ls -la",
    "find / -name '*.key' 2>/dev/null",
    "sudo -l",
    "cat .env",
]

DEFAULT_DB_LOG_QUERIES = [
    "SHOW DATABASES",
    "SHOW TABLES",
    "SELECT * FROM admin_users LIMIT 3",
    "SELECT * FROM payments LIMIT 3",
    "SELECT table_name FROM information_schema.tables WHERE table_schema='shophub'",
]

CONTAINER_MAP = {
    "http": "http_honeypot",
    "ssh": "ssh_honeypot",
    "database": "db_honeypot",
}


@dataclass
class CheckResult:
    name: str
    passed: bool
    details: Dict[str, Any]


def run_command(args: List[str], timeout: int = 20) -> Dict[str, Any]:
    try:
        proc = subprocess.run(
            args,
            text=True,
            capture_output=True,
            timeout=timeout,
            check=False,
        )
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    except Exception as exc:
        return {
            "ok": False,
            "returncode": None,
            "stdout": "",
            "stderr": str(exc),
        }


def response_fingerprint(text: str) -> str:
    normalized = "\n".join(line.rstrip() for line in str(text).splitlines()).strip()
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()[:16]


def score_response(text: str, expected_kind: str) -> Dict[str, Any]:
    body = str(text or "")
    lower = body.lower()
    honeytoken_hits = lower.count("honeytoken")
    deception_markers = sum(
        token in lower
        for token in [
            "api_key",
            "secret",
            "password",
            "access_key",
            "admin dashboard",
            "deploy_key",
            "mysql.user",
            "backup.sql",
            "nopasswd",
            "id_rsa",
        ]
    )
    error_markers = sum(
        token in lower
        for token in [
            "not found",
            "forbidden",
            "access denied",
            "command not found",
            "no such file or directory",
            "error 1045",
            "error 2013",
        ]
    )
    engagement = (
        honeytoken_hits * 5
        + deception_markers * 2
        + min(len(body) / 120.0, 8.0)
        - error_markers * 2
    )
    if expected_kind == "sensitive":
        engagement += deception_markers + honeytoken_hits * 2
    return {
        "bytes": len(body.encode("utf-8", errors="ignore")),
        "lines": len(body.splitlines()),
        "honeytoken_hits": honeytoken_hits,
        "deception_markers": deception_markers,
        "error_markers": error_markers,
        "engagement_score": round(engagement, 3),
        "fingerprint": response_fingerprint(body),
    }


def summarize_observations(observations: List[Dict[str, Any]]) -> Dict[str, Any]:
    usable = [obs for obs in observations if obs.get("ok") and "score" in obs]
    if not usable:
        return {"count": len(observations), "ok": 0}

    return {
        "count": len(observations),
        "ok": len(usable),
        "avg_engagement": mean(obs["score"]["engagement_score"] for obs in usable),
        "avg_bytes": mean(obs["score"]["bytes"] for obs in usable),
        "honeytoken_hits": sum(obs["score"]["honeytoken_hits"] for obs in usable),
        "deception_markers": sum(obs["score"]["deception_markers"] for obs in usable),
        "error_markers": sum(obs["score"]["error_markers"] for obs in usable),
        "unique_fingerprints": len({obs["score"]["fingerprint"] for obs in usable}),
    }


def print_phase_summary(label: str, phase_data: Dict[str, Any]) -> None:
    print(f"\n{label}")
    for protocol in ("http", "ssh", "database"):
        summary = phase_data.get(protocol, {}).get("summary", {})
        if not summary:
            continue
        print(
            f"  {protocol:8s} ok={summary.get('ok', 0)}/{summary.get('count', 0)} "
            f"engagement={summary.get('avg_engagement', 0):.2f} "
            f"honeytokens={summary.get('honeytoken_hits', 0)} "
            f"deception={summary.get('deception_markers', 0)} "
            f"errors={summary.get('error_markers', 0)}"
        )


def docker_rl_snapshot(container: str) -> Dict[str, Any]:
    code = (
        "import json, os, pickle\n"
        "from rl_core.config import RL_CONFIG\n"
        "path=RL_CONFIG['q_table_path']\n"
        "if not os.path.exists(path):\n"
        " print(json.dumps({'exists': False, 'path': path}))\n"
        " raise SystemExit(0)\n"
        "data=pickle.load(open(path,'rb'))\n"
        "q=data.get('q_table', {})\n"
        "actions={}\n"
        "for key, value in q.items():\n"
        " action=key[-1] if isinstance(key, tuple) and key else 'unknown'\n"
        " actions[action]=actions.get(action,0)+1\n"
        "vals=list(q.values())\n"
        "print(json.dumps({"
        " 'exists': True,"
        " 'path': path,"
        " 'q_table_size': len(q),"
        " 'epsilon': data.get('epsilon'),"
        " 'update_count': data.get('update_count'),"
        " 'action_counts': data.get('action_counts', {}),"
        " 'q_min': min(vals) if vals else None,"
        " 'q_max': max(vals) if vals else None,"
        " 'q_mean': sum(vals)/len(vals) if vals else None,"
        " 'learned_actions': actions,"
        "}))\n"
    )
    result = run_command(["docker", "exec", container, "python", "-c", code], timeout=20)
    if not result["ok"]:
        return {"exists": False, "error": result["stderr"] or result["stdout"]}
    try:
        stdout = result["stdout"].strip()
        candidate_lines = [line.strip() for line in stdout.splitlines() if line.strip().startswith("{")]
        if candidate_lines:
            return json.loads(candidate_lines[-1])
        return json.loads(stdout)
    except json.JSONDecodeError:
        return {"exists": False, "error": result["stdout"]}


def probe_http(host: str, port: int, scheme: str = "https") -> List[Dict[str, Any]]:
    observations: List[Dict[str, Any]] = []
    probe_types = {
        "/": "normal",
        "/admin": "sensitive",
        "/.env": "sensitive",
        "/.git/config": "sensitive",
        "/backup/database_backup.sql": "sensitive",
        "/api/config": "sensitive",
    }
    for path in DEFAULT_HTTP_PROBES:
        started = time.perf_counter()
        try:
            if scheme == "https":
                context = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(host, port, timeout=12, context=context)
            else:
                conn = http.client.HTTPConnection(host, port, timeout=12)
            conn.request("GET", path, headers={"User-Agent": "SigilHive-RL-Validator/1.0"})
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", errors="replace")
            conn.close()
            observations.append(
                {
                    "probe": path,
                    "ok": True,
                    "status": resp.status,
                    "elapsed": time.perf_counter() - started,
                    "score": score_response(body, probe_types.get(path, "normal")),
                    "preview": body[:240],
                }
            )
        except Exception as exc:
            observations.append({"probe": path, "ok": False, "error": str(exc)})
    return observations


async def probe_ssh(host: str, port: int, username: str, password: str) -> List[Dict[str, Any]]:
    try:
        import asyncssh
    except ImportError:
        return [{"probe": "ssh", "ok": False, "error": "asyncssh not installed"}]

    observations: List[Dict[str, Any]] = []
    try:
        async with asyncssh.connect(
            host,
            port=port,
            username=username,
            password=password,
            known_hosts=None,
            connect_timeout=10,
        ) as conn:
            stdin, stdout, stderr = await conn.open_session(term_type="xterm")
            await read_until_prompt(stdout)
            for cmd in DEFAULT_SSH_PROBES:
                started = time.perf_counter()
                stdin.write(cmd + "\r\n")
                await stdin.drain()
                raw = await read_until_prompt(stdout, command=cmd)
                text = clean_ssh_output(raw, cmd)
                observations.append(
                    {
                        "probe": cmd,
                        "ok": bool(text),
                        "elapsed": time.perf_counter() - started,
                        "score": score_response(
                            text,
                            "sensitive" if any(token in cmd for token in ("find", "sudo", ".env")) else "normal",
                        ),
                        "preview": text[:240],
                    }
                )
            with contextlib.suppress(Exception):
                stdin.write("exit\r\n")
                await stdin.drain()
    except Exception as exc:
        observations.append({"probe": "ssh", "ok": False, "error": str(exc)})
    return observations


async def read_until_prompt(stream: Any, timeout: int = 8, command: Optional[str] = None) -> str:
    import re

    marker = "$ "
    buf = ""
    command_seen = command is None
    command_text = command if command else ""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            chunk = await asyncio.wait_for(stream.read(4096), timeout=0.5)
            if not chunk:
                break
            buf += chunk if isinstance(chunk, str) else chunk.decode()
            clean = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", buf)
            if command_text and command_text in clean:
                command_seen = True
            prompt_count = clean.count(marker)
            required_prompts = 2 if command_text else 1
            if command_seen and prompt_count >= required_prompts:
                break
        except asyncio.TimeoutError:
            clean = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", buf)
            if command_text and command_text in clean:
                command_seen = True
            prompt_count = clean.count(marker)
            required_prompts = 2 if command_text else 1
            if command_seen and prompt_count >= required_prompts:
                break
    return buf


def clean_ssh_output(data: str, command: str) -> str:
    import re

    text = re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", data)
    lines = [line.rstrip("\r") for line in text.replace("\r\n", "\n").split("\n")]
    cleaned = []
    for line in lines:
        stripped = line.strip()
        if not stripped:
            continue
        if stripped == command.strip():
            continue
        if stripped.endswith("$") or stripped.endswith("$ "):
            continue
        if "@" in stripped and stripped.endswith("$"):
            continue
        cleaned.append(line)
    return "\n".join(cleaned).strip()


def try_probe_db_with_mysql(host: str, port: int, user: str, password: str, database: str) -> List[Dict[str, Any]]:
    mysql = shutil.which("mysql")
    if not mysql:
        return [{"probe": "database", "ok": False, "error": "mysql CLI not installed"}]

    observations: List[Dict[str, Any]] = []
    for query in DEFAULT_DB_LOG_QUERIES:
        started = time.perf_counter()
        result = run_command(
            [
                mysql,
                "-h",
                host,
                "-P",
                str(port),
                "-u",
                user,
                f"-p{password}",
                "--connect-timeout=8",
                "--batch",
                "--silent",
                "-e",
                f"USE {database}; {query}",
            ],
            timeout=35,
        )
        text = result["stdout"] if result["stdout"] else result["stderr"]
        observations.append(
            {
                "probe": query,
                "ok": result["ok"],
                "elapsed": time.perf_counter() - started,
                "score": score_response(text, "sensitive"),
                "preview": text[:240],
            }
        )
    return observations


def analyze_improvement(before: Dict[str, Any], after: Dict[str, Any], rl_before: Dict[str, Any], rl_after: Dict[str, Any]) -> Dict[str, Any]:
    protocol_results: Dict[str, Any] = {}
    passed_protocols = 0
    considered_protocols = 0

    for protocol in ("http", "ssh", "database"):
        before_summary = before.get(protocol, {}).get("summary", {})
        after_summary = after.get(protocol, {}).get("summary", {})
        before_rl = rl_before.get(protocol, {})
        after_rl = rl_after.get(protocol, {})

        if not before_summary or not after_summary:
            protocol_results[protocol] = {"evaluated": False}
            continue

        considered_protocols += 1
        engagement_delta = round(after_summary.get("avg_engagement", 0) - before_summary.get("avg_engagement", 0), 3)
        honeytoken_delta = after_summary.get("honeytoken_hits", 0) - before_summary.get("honeytoken_hits", 0)
        deception_delta = after_summary.get("deception_markers", 0) - before_summary.get("deception_markers", 0)
        error_delta = before_summary.get("error_markers", 0) - after_summary.get("error_markers", 0)
        q_growth = (after_rl.get("q_table_size") or 0) - (before_rl.get("q_table_size") or 0)
        update_growth = (after_rl.get("update_count") or 0) - (before_rl.get("update_count") or 0)
        epsilon_delta = round((before_rl.get("epsilon") or 0) - (after_rl.get("epsilon") or 0), 6)

        improved = (
            update_growth > 0
            and q_growth >= 0
            and (
                engagement_delta > 0.25
                or honeytoken_delta > 0
                or deception_delta > 0
                or error_delta > 0
            )
        )
        if improved:
            passed_protocols += 1

        protocol_results[protocol] = {
            "evaluated": True,
            "improved": improved,
            "engagement_delta": engagement_delta,
            "honeytoken_delta": honeytoken_delta,
            "deception_delta": deception_delta,
            "error_reduction": error_delta,
            "q_table_growth": q_growth,
            "update_growth": update_growth,
            "epsilon_drop": epsilon_delta,
        }

    overall_pass = considered_protocols > 0 and passed_protocols == considered_protocols
    return {
        "passed": overall_pass,
        "protocols": protocol_results,
        "passed_protocols": passed_protocols,
        "considered_protocols": considered_protocols,
    }


def run_offline_rl_checks(project_root: Path) -> List[CheckResult]:
    original_env = os.environ.copy()
    original_sys_path = list(sys.path)
    results: List[CheckResult] = []
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir)
        storage_dir = tmp / "storage"
        storage_dir.mkdir(parents=True, exist_ok=True)
        os.environ["RL_STORAGE_DIR"] = str(storage_dir)
        sys.path.insert(0, str(project_root))

        modules_to_clear = [
            name
            for name in list(sys.modules.keys())
            if name == "rl_core" or name.startswith("rl_core.")
        ]
        for name in modules_to_clear:
            sys.modules.pop(name, None)

        q_learning_agent = importlib.import_module("rl_core.q_learning_agent")
        reward_calculator = importlib.import_module("rl_core.reward_calculator")
        state_extractor = importlib.import_module("rl_core.state_extractor")
        structured_logger = importlib.import_module("rl_core.logging.structured_logger")
        action_dispatcher = importlib.import_module("rl_core.action_dispatcher")

        session_dir = storage_dir / "session_logs"
        (session_dir / "ssh").mkdir(parents=True, exist_ok=True)
        (session_dir / "http").mkdir(parents=True, exist_ok=True)
        (session_dir / "database").mkdir(parents=True, exist_ok=True)

        ssh_session = "ssh-unit"
        ssh_inputs = [
            ("whoami", True, {}),
            ("pwd", True, {}),
            ("ls -la", True, {}),
            ("find / -name '*.key'", True, {}),
            ("sudo -l", True, {}),
            ("cat .env", True, {}),
        ]
        for index, (input_data, success, metadata) in enumerate(ssh_inputs):
            structured_logger.log_interaction(
                ssh_session,
                "ssh",
                input_data,
                metadata=metadata,
                success=success,
            )
            log_path = session_dir / "ssh" / f"{ssh_session}.jsonl"
            lines = log_path.read_text(encoding="utf-8").strip().splitlines()
            last = json.loads(lines[-1])
            last["timestamp"] = float(index * 75)
            lines[-1] = json.dumps(last)
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        http_session = "http-unit"
        for index, path in enumerate(["GET /", "GET /admin", "GET /.env", "GET /api/config"]):
            structured_logger.log_interaction(
                http_session,
                "http",
                path,
                metadata={"status_code": 200 if index else 404},
                success=index != 0,
            )
            log_path = session_dir / "http" / f"{http_session}.jsonl"
            lines = log_path.read_text(encoding="utf-8").strip().splitlines()
            last = json.loads(lines[-1])
            last["timestamp"] = float(index * 90)
            lines[-1] = json.dumps(last)
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        db_session = "db-unit"
        for index, query in enumerate(DEFAULT_DB_LOG_QUERIES):
            structured_logger.log_interaction(
                db_session,
                "database",
                query,
                metadata={"intent": "read"},
                success="payments" not in query,
            )
            log_path = session_dir / "database" / f"{db_session}.jsonl"
            lines = log_path.read_text(encoding="utf-8").strip().splitlines()
            last = json.loads(lines[-1])
            last["timestamp"] = float(index * 60)
            lines[-1] = json.dumps(last)
            log_path.write_text("\n".join(lines) + "\n", encoding="utf-8")

        ssh_state = state_extractor.extract_state(ssh_session, "ssh")
        http_state = state_extractor.extract_state(http_session, "http")
        db_state = state_extractor.extract_state(db_session, "database")
        results.append(
            CheckResult(
                "state_extraction",
                ssh_state[1] >= 1 and ssh_state[2] >= 1 and ssh_state[4] == 1 and http_state[1] >= 1 and db_state[1] >= 1,
                {"ssh_state": ssh_state, "http_state": http_state, "database_state": db_state},
            )
        )

        positive_reward = reward_calculator.calculate_reward((1, 1, 0, 0, 0), (1, 3, 2, 0, 1), "ssh")
        negative_reward = reward_calculator.calculate_reward((1, 1, 0, 0, 0), (0, 1, 0, 2, 0), "ssh", terminal=True)
        results.append(
            CheckResult(
                "reward_shaping",
                positive_reward > 0 and negative_reward < 0,
                {"positive_reward": positive_reward, "negative_reward": negative_reward},
            )
        )

        cfg = dict(q_learning_agent.RL_CONFIG)
        cfg["q_table_path"] = str(storage_dir / "q_table.pkl")
        cfg["epsilon_start"] = 0.5
        cfg["epsilon_min"] = 0.1
        cfg["epsilon_decay"] = 0.8
        agent = q_learning_agent.QLearningAgent(cfg)
        state = (1, 2, 1, 0, 0)
        next_state = (1, 3, 2, 0, 1)
        action = "DECEPTIVE_RESOURCE"
        agent.update(state, action, reward=10.0, next_state=next_state)
        updated_q = agent.get_q_value(state, action)
        agent.save_q_table()
        saved_exists = Path(cfg["q_table_path"]).exists()
        reloaded = q_learning_agent.QLearningAgent(cfg)
        reloaded_q = reloaded.get_q_value(state, action)
        expected_q = cfg["learning_rate"] * 10.0
        results.append(
            CheckResult(
                "q_learning_update",
                math.isclose(updated_q, expected_q, rel_tol=1e-6)
                and reloaded_q > 0
                and reloaded.epsilon < cfg["epsilon_start"],
                {
                    "updated_q": updated_q,
                    "expected_q": expected_q,
                    "reloaded_q": reloaded_q,
                    "epsilon": reloaded.epsilon,
                    "saved_exists": saved_exists,
                },
            )
        )

        safe_actions = action_dispatcher.get_candidate_actions(protocol="ssh", state=(0, 0, 0, 0, 0), exploration=True)
        risky_actions = action_dispatcher.get_candidate_actions(protocol="ssh", state=(2, 2, 2, 2, 1), exploration=False)
        results.append(
            CheckResult(
                "action_gating",
                "TERMINATE_SESSION" not in safe_actions and "TERMINATE_SESSION" in risky_actions,
                {"safe_actions": safe_actions, "risky_actions": risky_actions},
            )
        )

    os.environ.clear()
    os.environ.update(original_env)
    sys.path[:] = original_sys_path
    return results


async def collect_live_phase(args: argparse.Namespace) -> Dict[str, Any]:
    phase: Dict[str, Any] = {}
    http_obs = probe_http(args.host, args.http_port, args.http_scheme)
    phase["http"] = {"observations": http_obs, "summary": summarize_observations(http_obs)}

    ssh_obs = await probe_ssh(args.host, args.ssh_port, args.ssh_user, args.ssh_password)
    phase["ssh"] = {"observations": ssh_obs, "summary": summarize_observations(ssh_obs)}

    db_obs = try_probe_db_with_mysql(args.host, args.db_port, args.db_user, args.db_password, args.db_name)
    phase["database"] = {"observations": db_obs, "summary": summarize_observations(db_obs)}
    return phase


async def run_training_rounds(args: argparse.Namespace) -> List[Dict[str, Any]]:
    rounds = []
    for round_no in range(1, args.rounds + 1):
        phase = await collect_live_phase(args)
        rounds.append({"round": round_no, "protocols": phase})
        print_phase_summary(f"Training round {round_no}", phase)
        if round_no < args.rounds:
            time.sleep(args.pause)
    return rounds


async def main() -> None:
    parser = argparse.ArgumentParser(description="Validate rl_core logic and live RL-driven honeypot improvement.")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, default=8443)
    parser.add_argument("--http-scheme", choices=["http", "https"], default="https")
    parser.add_argument("--ssh-port", type=int, default=5555)
    parser.add_argument("--db-port", type=int, default=2225)
    parser.add_argument("--ssh-user", default="shophub")
    parser.add_argument("--ssh-password", default="ShopHub121!")
    parser.add_argument("--db-user", default="shophub_app")
    parser.add_argument("--db-password", default="shophub123")
    parser.add_argument("--db-name", default="shophub")
    parser.add_argument("--rounds", type=int, default=6)
    parser.add_argument("--pause", type=float, default=0.5)
    parser.add_argument("--output", default="rl_validation_report.json")
    args = parser.parse_args()

    project_root = Path(__file__).resolve().parent
    report: Dict[str, Any] = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "offline_checks": [],
        "docker_rl_before": {},
        "docker_rl_after": {},
        "baseline_phase": {},
        "training_rounds": [],
        "post_training_phase": {},
        "improvement": {},
        "notes": [],
    }

    offline_checks = run_offline_rl_checks(project_root)
    report["offline_checks"] = [
        {"name": check.name, "passed": check.passed, "details": check.details}
        for check in offline_checks
    ]
    print("\nOffline RL-core checks")
    for check in offline_checks:
        status = "PASS" if check.passed else "FAIL"
        print(f"  {status:4s} {check.name}")

    for protocol, container in CONTAINER_MAP.items():
        report["docker_rl_before"][protocol] = docker_rl_snapshot(container)

    baseline_phase = await collect_live_phase(args)
    report["baseline_phase"] = baseline_phase
    print_phase_summary("Baseline phase", baseline_phase)

    training_rounds = await run_training_rounds(args)
    report["training_rounds"] = training_rounds

    post_training_phase = await collect_live_phase(args)
    report["post_training_phase"] = post_training_phase
    print_phase_summary("Post-training phase", post_training_phase)

    for protocol, container in CONTAINER_MAP.items():
        report["docker_rl_after"][protocol] = docker_rl_snapshot(container)

    report["improvement"] = analyze_improvement(
        baseline_phase,
        post_training_phase,
        report["docker_rl_before"],
        report["docker_rl_after"],
    )

    offline_pass = all(check.passed for check in offline_checks)
    live_pass = report["improvement"].get("passed", False)

    if not offline_pass:
        report["notes"].append("At least one direct rl_core invariant check failed.")
    if not live_pass:
        report["notes"].append(
            "Live improvement signal was weak or inconsistent. More rounds may be needed, or the current reward/action setup may not yet steer toward better responses."
        )
    if report["baseline_phase"].get("database", {}).get("summary", {}).get("ok", 0) == 0:
        report["notes"].append(
            "Database live probing was skipped or unavailable because the local mysql CLI is not installed."
        )

    output_path = project_root / args.output
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")

    print("\nImprovement verdict")
    print(
        f"  offline_checks={'PASS' if offline_pass else 'FAIL'} "
        f"live_improvement={'PASS' if live_pass else 'FAIL'} "
        f"report={output_path}"
    )


if __name__ == "__main__":
    asyncio.run(main())
