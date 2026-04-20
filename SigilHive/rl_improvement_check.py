import argparse
import asyncio
import hashlib
import http.client
import ssl
import json
import shutil
import subprocess
import time
from datetime import datetime, timezone
from pathlib import Path
from statistics import mean


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

DEFAULT_DB_PROBES = [
    "SHOW DATABASES",
    "SHOW TABLES",
    "SELECT * FROM admin_users LIMIT 3",
    "SELECT * FROM payments LIMIT 3",
    "SELECT table_name FROM information_schema.tables WHERE table_schema='shophub'",
]


def run_command(args, cwd=None, timeout=20):
    try:
        proc = subprocess.run(
            args,
            cwd=cwd,
            timeout=timeout,
            text=True,
            capture_output=True,
            check=False,
        )
        return {
            "ok": proc.returncode == 0,
            "returncode": proc.returncode,
            "stdout": proc.stdout.strip(),
            "stderr": proc.stderr.strip(),
        }
    except Exception as exc:
        return {"ok": False, "returncode": None, "stdout": "", "stderr": str(exc)}


def response_fingerprint(text):
    normalized = "\n".join(line.rstrip() for line in str(text).splitlines()).strip()
    return hashlib.sha256(normalized.encode("utf-8", errors="ignore")).hexdigest()[:16]


def score_response(text):
    body = str(text)
    lower = body.lower()
    honeytoken_hits = lower.count("honeytoken")
    sensitive_hits = sum(
        token in lower
        for token in [
            "password",
            "secret",
            "api_key",
            "access_key",
            "stripe",
            "admin",
            "id_rsa",
            "mysql.user",
        ]
    )
    error_hits = sum(
        token in lower
        for token in [
            "not found",
            "forbidden",
            "access denied",
            "command not found",
            "error 1045",
            "error 2013",
        ]
    )
    return {
        "bytes": len(body.encode("utf-8", errors="ignore")),
        "lines": len(body.splitlines()),
        "honeytoken_hits": honeytoken_hits,
        "sensitive_hits": sensitive_hits,
        "error_hits": error_hits,
        "fingerprint": response_fingerprint(body),
    }


def snapshot_rl(container):
    code = (
        "import json, os, pickle\n"
        "path='storage/q_table.pkl'\n"
        "if not os.path.exists(path):\n"
        " print(json.dumps({'exists': False}))\n"
        " raise SystemExit(0)\n"
        "data=pickle.load(open(path,'rb'))\n"
        "q=data.get('q_table', {})\n"
        "vals=list(q.values())\n"
        "top=sorted(q.items(), key=lambda kv: kv[1], reverse=True)[:10]\n"
        "print(json.dumps({\n"
        " 'exists': True,\n"
        " 'q_table_size': len(q),\n"
        " 'epsilon': data.get('epsilon'),\n"
        " 'update_count': data.get('update_count'),\n"
        " 'action_counts': data.get('action_counts', {}),\n"
        " 'q_min': min(vals) if vals else None,\n"
        " 'q_max': max(vals) if vals else None,\n"
        " 'q_mean': sum(vals)/len(vals) if vals else None,\n"
        " 'top_actions': [{'state': str(k[0]), 'action': k[1], 'q': v} for k, v in top],\n"
        "}))\n"
    )
    result = run_command(["docker", "exec", container, "python", "-c", code], timeout=20)
    if not result["ok"]:
        return {"exists": False, "error": result["stderr"] or result["stdout"]}
    try:
        return json.loads(result["stdout"])
    except json.JSONDecodeError:
        return {"exists": False, "error": result["stdout"]}


def probe_http(host, port, paths, scheme="https"):
    observations = []
    for path in paths:
        started = time.perf_counter()
        try:
            if scheme == "https":
                context = ssl._create_unverified_context()
                conn = http.client.HTTPSConnection(
                    host, port, timeout=12, context=context
                )
            else:
                conn = http.client.HTTPConnection(host, port, timeout=12)
            conn.request("GET", path, headers={"User-Agent": "SigilHive-RL-Evaluator/1.0"})
            resp = conn.getresponse()
            body = resp.read().decode("utf-8", errors="replace")
            elapsed = time.perf_counter() - started
            observations.append(
                {
                    "probe": path,
                    "ok": True,
                    "status": resp.status,
                    "elapsed": elapsed,
                    "score": score_response(body),
                    "preview": body[:240],
                }
            )
            conn.close()
        except Exception as exc:
            observations.append({"probe": path, "ok": False, "error": str(exc)})
    return observations


async def probe_ssh(host, port, username, password, commands):
    try:
        import asyncssh
    except ImportError:
        return [
            {
                "ok": False,
                "error": (
                    "asyncssh is not installed in this Python environment; "
                    "install it with: python -m pip install asyncssh"
                ),
            }
        ]

    observations = []
    try:
        async with asyncssh.connect(
            host,
            port=port,
            username=username,
            password=password,
            known_hosts=None,
            connect_timeout=8,
            request_pty="force",
        ) as conn:
            proc = await conn.create_process(term_type="xterm", encoding=None)
            await read_until_prompt(proc)
            for cmd in commands:
                started = time.perf_counter()
                proc.stdin.write((cmd + "\r\n").encode())
                await proc.stdin.drain()
                raw = await read_until_prompt(proc, command=cmd)
                elapsed = time.perf_counter() - started
                text = clean_ssh_output(raw, cmd)
                observations.append(
                    {
                        "probe": cmd,
                        "ok": bool(text),
                        "error": None if text else "empty command output",
                        "elapsed": elapsed,
                        "score": score_response(text),
                        "preview": text[:240],
                    }
                )
            proc.stdin.write(b"exit\r\n")
            await proc.stdin.drain()
            proc.close()
    except Exception as exc:
        observations.append({"ok": False, "error": str(exc)})
    return observations


async def read_until_prompt(process, timeout=8, command=None):
    import re

    marker = b"$ "
    buf = b""
    command_seen = command is None
    command_bytes = command.encode() if command else b""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        try:
            chunk = await asyncio.wait_for(process.stdout.read(4096), timeout=0.5)
            if not chunk:
                break
            buf += chunk if isinstance(chunk, bytes) else chunk.encode()
            clean = re.sub(rb"\x1b\[[0-9;]*[A-Za-z]", b"", buf)
            if command_bytes and command_bytes in clean:
                command_seen = True
            if command_seen and marker in clean:
                break
        except asyncio.TimeoutError:
            clean = re.sub(rb"\x1b\[[0-9;]*[A-Za-z]", b"", buf)
            if command_bytes and command_bytes in clean:
                command_seen = True
            if command_seen and marker in clean:
                break
    return buf


def clean_ssh_output(data, command):
    text = strip_ansi(data).decode("utf-8", errors="replace")
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
        if "@" in stripped and ":~" in stripped and stripped.endswith("$"):
            continue
        cleaned.append(line)

    return "\n".join(cleaned).strip()


def strip_ansi(data):
    import re

    return re.sub(rb"\x1b\[[0-9;]*[A-Za-z]", b"", data)


def probe_db(host, port, user, password, queries, database="shophub"):
    mysql = shutil.which("mysql")
    if not mysql:
        return [{"ok": False, "error": "mysql CLI is not installed or not in PATH; skipping DB probes"}]

    observations = []
    for query in queries:
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
                "--database",
                database,
                "-e",
                query,
            ],
            timeout=35,
        )
        elapsed = time.perf_counter() - started
        text = result["stdout"] if result["stdout"] else result["stderr"]
        observations.append(
            {
                "probe": query,
                "ok": result["ok"],
                "elapsed": elapsed,
                "score": score_response(text),
                "preview": text[:240],
            }
        )
    return observations


def summarize_observations(observations):
    usable = [obs for obs in observations if obs.get("ok") and "score" in obs]
    if not usable:
        return {"count": len(observations), "ok": 0}

    return {
        "count": len(observations),
        "ok": len(usable),
        "avg_bytes": mean(obs["score"]["bytes"] for obs in usable),
        "avg_lines": mean(obs["score"]["lines"] for obs in usable),
        "honeytoken_hits": sum(obs["score"]["honeytoken_hits"] for obs in usable),
        "sensitive_hits": sum(obs["score"]["sensitive_hits"] for obs in usable),
        "error_hits": sum(obs["score"]["error_hits"] for obs in usable),
        "unique_fingerprints": len({obs["score"]["fingerprint"] for obs in usable}),
    }


def print_round_summary(round_data):
    print(f"\nRound {round_data['round']}")
    for protocol in ["http", "ssh", "database"]:
        summary = round_data["protocols"].get(protocol, {}).get("summary", {})
        rl = round_data["rl_snapshots"].get(protocol, {})
        print(
            f"  {protocol:8s} ok={summary.get('ok', 0)}/{summary.get('count', 0)} "
            f"honeytokens={summary.get('honeytoken_hits', 0)} "
            f"sensitive={summary.get('sensitive_hits', 0)} "
            f"errors={summary.get('error_hits', 0)} "
            f"q_entries={rl.get('q_table_size', 'n/a')} "
            f"updates={rl.get('update_count', 'n/a')} "
            f"epsilon={rl.get('epsilon', 'n/a')}"
        )


async def main():
    parser = argparse.ArgumentParser(
        description="Exercise SigilHive honeypots and track whether RL response behavior changes."
    )
    parser.add_argument("--rounds", type=int, default=5)
    parser.add_argument("--pause", type=float, default=1.0)
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--http-port", type=int, default=8443)
    parser.add_argument("--http-scheme", choices=["http", "https"], default="https")
    parser.add_argument("--ssh-port", type=int, default=5555)
    parser.add_argument("--db-port", type=int, default=2225)
    parser.add_argument("--db-name", default="shophub")
    parser.add_argument("--ssh-user", default="shophub")
    parser.add_argument("--ssh-password", default="ShopHub121!")
    parser.add_argument("--db-user", default="shophub_app")
    parser.add_argument("--db-password", default="shophub123")
    parser.add_argument("--output", default="rl_improvement_report.json")
    parser.add_argument("--skip-ssh", action="store_true")
    parser.add_argument("--skip-db", action="store_true")
    args = parser.parse_args()

    report = {
        "created_at": datetime.now(timezone.utc).isoformat(),
        "rounds_requested": args.rounds,
        "notes": [
            "Improvement is inferred from Q-table growth, epsilon decay, action preference changes, fewer errors, and richer/honeytoken responses.",
            "A few rounds are usually not enough for stable learning; run 20-50 rounds for clearer trends.",
        ],
        "rounds": [],
    }

    containers = {
        "http": "http_honeypot",
        "ssh": "ssh_honeypot",
        "database": "db_honeypot",
    }

    for round_no in range(1, args.rounds + 1):
        round_data = {
            "round": round_no,
            "protocols": {},
            "rl_snapshots": {},
        }

        http_obs = probe_http(
            args.host, args.http_port, DEFAULT_HTTP_PROBES, args.http_scheme
        )
        round_data["protocols"]["http"] = {
            "observations": http_obs,
            "summary": summarize_observations(http_obs),
        }

        if not args.skip_ssh:
            ssh_obs = await probe_ssh(
                args.host,
                args.ssh_port,
                args.ssh_user,
                args.ssh_password,
                DEFAULT_SSH_PROBES,
            )
            round_data["protocols"]["ssh"] = {
                "observations": ssh_obs,
                "summary": summarize_observations(ssh_obs),
            }

        if not args.skip_db:
            db_obs = probe_db(
                args.host,
                args.db_port,
                args.db_user,
                args.db_password,
                DEFAULT_DB_PROBES,
                args.db_name,
            )
            round_data["protocols"]["database"] = {
                "observations": db_obs,
                "summary": summarize_observations(db_obs),
            }

        for protocol, container in containers.items():
            if protocol not in round_data["protocols"]:
                continue
            round_data["rl_snapshots"][protocol] = snapshot_rl(container)

        report["rounds"].append(round_data)
        print_round_summary(round_data)

        if round_no < args.rounds:
            time.sleep(args.pause)

    output_path = Path(args.output)
    output_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\nWrote report: {output_path.resolve()}")


if __name__ == "__main__":
    asyncio.run(main())
