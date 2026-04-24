import os
import time
import random
import importlib.util
from typing import Dict, Any, Optional
from datetime import datetime, timezone
from pathlib import Path
from llm_gen import generate_response_for_command_async
from kafka_manager import HoneypotKafkaManager
from rl_core.q_learning_agent import shared_rl_agent
from rl_core.state_extractor import extract_state
from rl_core.reward_calculator import calculate_reward
from rl_core.logging.structured_logger import log_interaction
from rl_core.config import BASELINE_CONFIG


def _resolve_file_structure_path() -> Path:
    env_path = os.getenv("FILE_STRUCTURE_PATH", "").strip()
    if env_path:
        return Path(env_path).resolve()
    script_dir = Path(__file__).resolve().parent
    candidates = [
        script_dir / "file_structure.py",
        script_dir.parent / "file_structure.py",
    ]
    for candidate in candidates:
        if candidate.exists():
            return candidate.resolve()
    return candidates[0].resolve()


class Controller:
    def __init__(self, persona: str = "shophub-server"):
        self.sessions: Dict[str, Dict[str, Any]] = {}
        self.persona = persona
        self.kafka_manager = HoneypotKafkaManager()
        self.file_structure_path = _resolve_file_structure_path()
        self._file_mtime = 0.0
        self.file_structure = {}
        self.file_contents = {}
        self._reload_file_structure(force=True)

        self.rl_agent = shared_rl_agent
        self.rl_enabled = os.getenv("RL_ENABLED", "true").lower() == "true"
        print(f"[Controller] ✅ Controller initialized (RL enabled: {self.rl_enabled})")

    def _reload_file_structure(self, force: bool = False):
        try:
            mtime = self.file_structure_path.stat().st_mtime
        except FileNotFoundError:
            return

        if not force and mtime <= self._file_mtime:
            return

        spec = importlib.util.spec_from_file_location(
            f"_ssh_fs_{int(mtime * 1000)}",
            self.file_structure_path,
        )
        if spec is None or spec.loader is None:
            return

        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.file_structure = getattr(mod, "SHOPHUB_STRUCTURE", {})
        self.file_contents = getattr(mod, "FILE_CONTENTS", {})
        self._file_mtime = mtime
        print(f"[Controller] Reloaded file structure from {self.file_structure_path}")

    def _update_meta(self, session_id: str, event: Dict[str, Any]):
        meta = self.sessions.setdefault(
            session_id,
            {
                "cmd_count": 0,
                "elapsed": 0.0,
                "last_cmd": "",
                "current_dir": "~",
                "command_history": [],
                "pending_rl": None,
            },
        )
        meta["cmd_count"] = event.get("cmd_count", meta["cmd_count"])
        meta["elapsed"] = event.get("elapsed", meta["elapsed"])

        if "command" in event:
            cmd = event.get("command", meta["last_cmd"])
            meta["last_cmd"] = cmd
            meta["command_history"].append(cmd)
            if len(meta["command_history"]) > 50:
                meta["command_history"] = meta["command_history"][-50:]

        if "current_dir" in event:
            meta["current_dir"] = event.get("current_dir", meta["current_dir"])

        meta["last_ts"] = time.time()
        self.sessions[session_id] = meta
        return meta

    def _response_success(self, response: Dict[str, Any]) -> bool:
        text = str(response.get("response", "")).lower()
        error_markers = (
            "command not found",
            "no such file or directory",
            "permission denied",
            "missing file operand",
            "usage:",
            "fatal:",
            "error",
        )
        return not any(marker in text for marker in error_markers)

    def _update_pending_rl(
        self, session_id: str, curr_state: tuple, terminal: bool = False
    ):
        meta = self.sessions.get(session_id)
        if not meta:
            return

        pending = meta.get("pending_rl")
        if not pending:
            return

        reward = calculate_reward(
            pending["state"], curr_state, protocol="ssh", terminal=terminal
        )
        self.rl_agent.update(pending["state"], pending["action"], reward, curr_state)
        meta["pending_rl"] = None

        if terminal:
            self.rl_agent.save_q_table()

    def get_directory_context(self, current_dir: str) -> Dict[str, Any]:
        self._reload_file_structure()
        normalized_dir = current_dir.strip()
        if normalized_dir.endswith("/") and normalized_dir != "/":
            normalized_dir = normalized_dir[:-1]
        if normalized_dir == "~" or normalized_dir == "":
            normalized_dir = "~"
        if normalized_dir in self.file_structure:
            return self.file_structure[normalized_dir]
        if not normalized_dir.startswith("~") and normalized_dir.startswith("/"):
            pass
        elif not normalized_dir.startswith("~"):
            maybe = f"~/{normalized_dir}"
            if maybe in self.file_structure:
                return self.file_structure[maybe]
        return {
            "type": "directory",
            "description": f"Directory: {current_dir}",
            "contents": [],
        }

    def classify_command(self, cmd: str) -> str:
        cmd = (cmd or "").strip()
        if cmd == "":
            return "noop"
        cmd_parts = cmd.split()
        base_cmd = cmd_parts[0] if cmd_parts else ""
        if base_cmd in ("clear", "reset"):
            return "clear_screen"
        if base_cmd == "history":
            return "show_history"
        if base_cmd == "echo":
            return "echo"
        if base_cmd in ("env", "printenv"):
            return "show_env"
        if base_cmd in ("cat", "less", "more"):
            return "read_file_no_arg" if len(cmd_parts) < 2 else "read_file"
        if base_cmd in ("l", "ls", "dir", "ll"):
            return "list_dir"
        if base_cmd in ("whoami", "id"):
            return "identity"
        if base_cmd in ("uname", "hostname"):
            return "system_info"
        if base_cmd in ("ps", "top", "htop"):
            return "process_list"
        if base_cmd in ("netstat", "ss"):
            return "netstat"
        if base_cmd == "ping":
            return "network_probe"
        if base_cmd in ("curl", "wget"):
            return "http_fetch"
        if base_cmd == "pwd":
            return "print_dir"
        if base_cmd in ("find", "locate"):
            return "search"
        if base_cmd in ("grep", "egrep"):
            return "grep_no_arg" if len(cmd_parts) < 2 else "grep"
        if base_cmd in ("tail", "head"):
            return "file_peek"
        if base_cmd == "df":
            return "disk_usage"
        if base_cmd == "free":
            return "memory_info"
        if base_cmd in ("docker", "docker-compose"):
            return "docker"
        if base_cmd in ("npm", "node"):
            return "nodejs"
        if base_cmd == "git":
            return "git"
        if base_cmd.startswith("sudo"):
            return "privilege_escalation"
        if base_cmd == "ssh":
            return "remote_ssh"
        return "unknown"

    def _file_exists_in_directory(self, current_dir: str, filename: str) -> bool:
        dir_context = self.get_directory_context(current_dir)
        contents = dir_context.get("contents", [])
        filename_lower = filename.lower()
        for item in contents:
            if item.lower() == filename_lower:
                return True
        return False

    def _find_file_case_insensitive(
        self, current_dir: str, filename: str
    ) -> Optional[str]:
        self._reload_file_structure()
        if filename.startswith("~") or filename.startswith("/"):
            full_path = filename
        else:
            sep = "" if current_dir.endswith("/") else "/"
            full_path = f"{current_dir}{sep}{filename}"
        full_path = full_path.replace("//", "/")
        if full_path in self.file_contents:
            return full_path
        full_path_lower = full_path.lower()
        for key in self.file_contents.keys():
            if key.lower() == full_path_lower:
                return key
        return None

    async def _finalize(
        self,
        session_id: str,
        cmd: str,
        intent: str,
        current_dir: str,
        response: str,
        delay: float,
    ):
        try:
            payload = {
                "session_id": session_id,
                "command": cmd,
                "intent": intent,
                "current_dir": current_dir,
                "response": response,
                "delay": delay,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self.kafka_manager.send(topic="SSHtoHTTP", value=payload)
            self.kafka_manager.send(topic="SSHtoDB", value=payload)
            self.kafka_manager.send_dashboard(
                topic="honeypot-logs",
                value={
                    "timestamp": payload["timestamp"],
                    "session_id": session_id,
                    "command": cmd,
                    "intent": intent,
                    "current_dir": current_dir,
                },
                service="ssh",
                event_type=intent,
            )
        except Exception as e:
            print(f"[controller] kafka error in finalize: {e}")

        return {"response": response, "delay": delay}

    # ──────────────────────────────────────────────────────────────────
    # FIX 1: corrected RL integration
    # Previous version called:
    #   extract_state(meta, intent)             ← wrong signature
    #   self.rl_agent.get_state_index(state)    ← method doesn't exist
    #   self.rl_agent.choose_action(state_idx)  ← method doesn't exist
    #   calculate_reward(meta, next_meta, intent, action) ← wrong signature
    # ──────────────────────────────────────────────────────────────────
    async def get_action_for_session(
        self, session_id: str, event: Dict[str, Any]
    ) -> Dict[str, Any]:
        meta = self._update_meta(session_id, event)
        cmd = meta.get("last_cmd", "")
        intent = self.classify_command(cmd)

        state = extract_state(session_id, protocol="ssh")
        if self.rl_enabled:
            self._update_pending_rl(session_id, state)

        if not self.rl_enabled:
            action_result = await self._original_command_handler(session_id, event)
            log_interaction(
                session_id=session_id,
                protocol="ssh",
                input_data=cmd,
                metadata={
                    "intent": intent,
                    "current_dir": meta.get("current_dir", "~"),
                    "cmd_count": meta.get("cmd_count", 0),
                    "response_action": "BASELINE",
                },
                success=self._response_success(action_result),
            )
            return action_result

        try:
            action = self.rl_agent.select_action(state)

            action_result = await self._execute_rl_action(action, session_id, event)

            log_interaction(
                session_id=session_id,
                protocol="ssh",
                input_data=cmd,
                metadata={
                    "intent": intent,
                    "current_dir": meta.get("current_dir", "~"),
                    "cmd_count": meta.get("cmd_count", 0),
                    "response_action": action,
                },
                success=self._response_success(action_result),
            )
            meta["pending_rl"] = {"state": state, "action": action}

            return action_result

        except Exception as e:
            print(f"[Controller] RL error (falling back): {e}")
            import traceback

            traceback.print_exc()
            return await self._original_command_handler(session_id, event)

    async def _original_command_handler(
        self, session_id: str, event: Dict[str, Any]
    ) -> Dict[str, Any]:
        meta = self.sessions.get(session_id, {})
        cmd = meta.get("last_cmd", "")
        current_dir = meta.get("current_dir", "~")
        intent = self.classify_command(cmd)
        dir_context = self.get_directory_context(current_dir)
        context = {
            "current_directory": current_dir,
            "directory_description": dir_context.get("description", ""),
            "directory_contents": dir_context.get("contents", []),
            "application": "ShopHub E-commerce Platform",
            "application_tech": "Node.js, Express, MongoDB, Redis",
        }

        if intent == "clear_screen":
            return await self._finalize(
                session_id, cmd, intent, current_dir, "\033[H\033[2J", 0.0
            )
        elif intent == "show_history":
            hist = meta.get("command_history", [])
            numbered = "\n".join(f"  {i + 1}  {c}" for i, c in enumerate(hist[-20:]))
            return await self._finalize(
                session_id, cmd, intent, current_dir, numbered, 0.1
            )
        elif intent == "echo":
            text = cmd[4:].strip() if len(cmd) > 4 else ""
            return await self._finalize(session_id, cmd, intent, current_dir, text, 0.0)
        elif intent == "show_env":
            env_vars = (
                "HOME=/home/shophub\nUSER=shophub\nSHELL=/bin/bash\n"
                "PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin\n"
                "NODE_ENV=production\nPORT=3000\nDB_HOST=prod-mysql.internal\n"
                "REDIS_HOST=prod-redis.internal"
            )
            return await self._finalize(
                session_id, cmd, intent, current_dir, env_vars, 0.1
            )
        elif intent == "read_file_no_arg":
            base_cmd = cmd.split()[0] if cmd.split() else "cat"
            return await self._finalize(
                session_id,
                cmd,
                intent,
                current_dir,
                f"{base_cmd}: missing file operand\nTry '{base_cmd} --help' for more information.",
                0.05,
            )
        elif intent == "read_file":
            return await self._handle_read_file(session_id, cmd, current_dir, context)
        elif intent == "list_dir":
            return await self._handle_list_dir(session_id, cmd, current_dir, context)
        elif intent == "identity":
            if "whoami" in cmd:
                return await self._finalize(
                    session_id, cmd, intent, current_dir, "shophub", 0.05
                )
            else:
                return await self._finalize(
                    session_id,
                    cmd,
                    intent,
                    current_dir,
                    "uid=1000(shophub) gid=1000(shophub) groups=1000(shophub),27(sudo),999(docker)",
                    0.05,
                )
        elif intent == "system_info":
            if "uname" in cmd:
                if "-a" in cmd:
                    return await self._finalize(
                        session_id,
                        cmd,
                        intent,
                        current_dir,
                        "Linux shophub-prod-01 5.15.0-89-generic #99-Ubuntu SMP Mon Oct 30 20:42:41 UTC 2023 x86_64 x86_64 x86_64 GNU/Linux",
                        0.05,
                    )
                return await self._finalize(
                    session_id, cmd, intent, current_dir, "Linux", 0.05
                )
            else:
                return await self._finalize(
                    session_id, cmd, intent, current_dir, "shophub-prod-01", 0.05
                )
        elif intent == "process_list":
            return await self._finalize(
                session_id, cmd, intent, current_dir, self._simulate_ps(cmd), 0.1
            )
        elif intent == "netstat":
            return await self._finalize(
                session_id, cmd, intent, current_dir, self._simulate_netstat(cmd), 0.1
            )
        elif intent == "print_dir":
            full_path = current_dir
            if full_path == "~":
                full_path = "/home/shophub"
            elif full_path.startswith("~/"):
                full_path = "/home/shophub/" + full_path[2:]
            return await self._finalize(
                session_id, cmd, intent, current_dir, full_path, 0.05
            )
        elif intent == "docker":
            return await self._finalize(
                session_id, cmd, intent, current_dir, self._simulate_docker(cmd), 0.1
            )
        elif intent == "git":
            git_output = self._simulate_git(cmd, dir_context)
            return await self._finalize(
                session_id, cmd, intent, current_dir, git_output, 0.1
            )
        elif intent == "grep_no_arg":
            base_cmd = cmd.split()[0] if cmd.split() else "grep"
            return await self._finalize(
                session_id,
                cmd,
                intent,
                current_dir,
                f"Usage: {base_cmd} [OPTION]... PATTERN [FILE]...\nTry '{base_cmd} --help' for more information.",
                0.05,
            )
        else:
            base_cmd = cmd.split()[0] if cmd.split() else "unknown"
            return await self._finalize(
                session_id,
                cmd,
                intent,
                current_dir,
                f"bash: {base_cmd}: command not found",
                0.05,
            )

    async def _handle_read_file(self, session_id, cmd, current_dir, context):
        parts = cmd.split(maxsplit=1)
        if len(parts) < 2:
            return await self._finalize(
                session_id,
                cmd,
                "read_file_no_arg",
                current_dir,
                f"{parts[0]}: missing file operand",
                0.05,
            )
        filename = parts[1].strip()
        intent = "read_file"
        if not self._file_exists_in_directory(current_dir, filename):
            return await self._finalize(
                session_id,
                cmd,
                intent,
                current_dir,
                f"{parts[0]}: {filename}: No such file or directory",
                0.05,
            )
        file_path_key = self._find_file_case_insensitive(current_dir, filename)
        if file_path_key:
            content = self.file_contents[file_path_key]
            return await self._finalize(
                session_id, cmd, intent, current_dir, content, 0.1
            )
        llm_response = await generate_response_for_command_async(
            command=cmd,
            filename_hint=filename,
            persona=self.persona,
            context=context,
            force_refresh=False,
        )
        return await self._finalize(
            session_id, cmd, intent, current_dir, llm_response, 0.1
        )

    async def _handle_list_dir(self, session_id, cmd, current_dir, context):
        parts = cmd.split()
        target_dir = current_dir
        if len(parts) > 1 and not parts[1].startswith("-"):
            target_dir = parts[1]
        dir_context = self.get_directory_context(target_dir)
        contents = dir_context.get("contents", [])
        if not contents and target_dir in ("~", ".", ""):
            contents = [
                "shophub",
                ".env",
                ".bashrc",
                ".bash_history",
                ".profile",
                ".ssh",
                "README.md",
            ]
        if not contents:
            return await self._finalize(
                session_id, cmd, "list_dir", current_dir, "", 0.05
            )
        if "-la" in cmd or "-al" in cmd or "-l" in cmd:
            listing_parts = [f"total {len(contents) * 4}"]
            for item in contents:
                if item.startswith("."):
                    perm = "drwxr-xr-x" if item == ".git" else "-rw-r--r--"
                    size = "4096" if item == ".git" else str(random.randint(100, 5000))
                elif item.endswith("/"):
                    perm, size = "drwxr-xr-x", "4096"
                    item = item.rstrip("/")
                elif any(
                    item.endswith(ext) for ext in [".js", ".json", ".md", ".txt", ".sh"]
                ):
                    perm, size = "-rw-r--r--", str(random.randint(500, 10000))
                else:
                    perm, size = "drwxr-xr-x", "4096"
                listing_parts.append(
                    f"{perm} 1 shophub shophub {size:>8} Jan 15 10:30 {item}"
                )
            return await self._finalize(
                session_id, cmd, "list_dir", current_dir, "\n".join(listing_parts), 0.1
            )
        else:
            listing = "  ".join(contents)
            return await self._finalize(
                session_id, cmd, "list_dir", current_dir, listing, 0.05
            )

    def _simulate_ps(self, cmd):
        if "aux" in cmd or "-ef" in cmd:
            return (
                "USER       PID %CPU %MEM    VSZ   RSS TTY      STAT START   TIME COMMAND\n"
                "root         1  0.0  0.1  22536  3892 ?        Ss   10:00   0:01 /sbin/init\n"
                "shophub   1234  2.5  5.2 987654 98765 ?        Sl   10:05   1:23 node /home/shophub/shophub/server.js\n"
                "mongodb   2345  1.2  3.4 678901 45678 ?        Sl   10:00   0:45 /usr/bin/mongod --config /etc/mongod.conf\n"
                "redis     3456  0.3  0.8 234567 12345 ?        Ssl  10:00   0:12 /usr/bin/redis-server *:6379"
            )
        return "  PID TTY          TIME CMD\n 1234 pts/0    00:00:00 bash\n 5678 pts/0    00:00:00 ps"

    def _simulate_netstat(self, cmd):
        return (
            "Active Internet connections (only servers)\n"
            "Proto Recv-Q Send-Q Local Address           Foreign Address         State\n"
            "tcp        0      0 0.0.0.0:3000            0.0.0.0:*               LISTEN\n"
            "tcp        0      0 0.0.0.0:22              0.0.0.0:*               LISTEN\n"
            "tcp        0      0 127.0.0.1:6379          0.0.0.0:*               LISTEN\n"
            "tcp        0      0 127.0.0.1:27017         0.0.0.0:*               LISTEN"
        )

    def _simulate_docker(self, cmd):
        if "ps" in cmd:
            return (
                "CONTAINER ID   IMAGE           COMMAND        CREATED      STATUS      PORTS                    NAMES\n"
                'a1b2c3d4e5f6   shophub:latest  "node server"  2 hours ago  Up 2 hours  0.0.0.0:3000->3000/tcp   shophub_app\n'
            )
        if "images" in cmd:
            return "REPOSITORY   TAG       IMAGE ID       CREATED       SIZE\nshophub       latest    abcdef012345   2 hours ago   200MB"
        return "docker: unknown command"

    def _simulate_git(self, cmd, dir_context):
        if ".git" in dir_context.get("contents", []):
            if cmd.strip() == "git status":
                return "On branch main\nYour branch is up to date with 'origin/main'.\n\nnothing to commit, working tree clean"
            return f"git: simulated output for '{cmd}'"
        return "fatal: not a git repository (or any of the parent directories): .git"

    async def _execute_rl_action(self, action, session_id, event):
        meta = self.sessions[session_id]
        cmd = meta.get("last_cmd", "")
        current_dir = meta.get("current_dir", "~")
        intent = self.classify_command(cmd)

        if action == "REALISTIC_RESPONSE":
            return await self._original_command_handler(session_id, event)

        elif action == "DECEPTIVE_RESOURCE":
            cmd_lower = cmd.lower()
            if "passwd" in cmd_lower and "etc" in cmd_lower:
                fake_passwd = (
                    "root:x:0:0:root:/root:/bin/bash\n"
                    "shophub:x:1000:1000:ShopHub App:/home/shophub:/bin/bash\n"
                    "admin:x:1001:1001:Admin User:/home/admin:/bin/bash\n"
                    "deploy:x:1003:1003:Deployment:/home/deploy:/bin/bash"
                )
                return await self._finalize(
                    session_id, cmd, intent, current_dir, fake_passwd, 0.05
                )
            if "shadow" in cmd_lower and "etc" in cmd_lower:
                fake_shadow = (
                    "root:$6$HONEYTOKEN_ROOT_001:19000:0:99999:7:::\n"
                    "shophub:$6$HONEYTOKEN_APP_002:19000:0:99999:7:::\n"
                    "admin:$6$HONEYTOKEN_ADMIN_003:19000:0:99999:7:::"
                )
                return await self._finalize(
                    session_id, cmd, intent, current_dir, fake_shadow, 0.05
                )
            if ".env" in cmd_lower:
                fake_env = (
                    "NODE_ENV=production\nPORT=3000\n"
                    "DB_USER=shophub_prod_HONEYTOKEN_001\n"
                    "DB_PASS=Pr0dP@ssw0rd_HONEYTOKEN_DB_001\n"
                    "AWS_ACCESS_KEY_ID=AKIA_HONEYTOKEN_AWS_KEY_001\n"
                    "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI_HONEYTOKEN_AWS_SECRET\n"
                    "STRIPE_SECRET_KEY=sk_live_HONEYTOKEN_STRIPE_SECRET_KEY_001\n"
                    "JWT_SECRET=jwt_super_secret_HONEYTOKEN_003"
                )
                return await self._finalize(
                    session_id, cmd, intent, current_dir, fake_env, 0.05
                )
            return await self._original_command_handler(session_id, event)

        elif action == "RESPONSE_DELAY":
            response = await self._original_command_handler(session_id, event)
            response["delay"] = response.get("delay", 0.0) + random.uniform(0.5, 2.0)
            return response

        elif action == "MISLEADING_SUCCESS":
            # Keep basic shell navigation usable; deceptive empties here make the
            # honeypot feel broken rather than believable.
            if intent in {"list_dir", "print_dir", "read_file", "read_file_no_arg"}:
                return await self._original_command_handler(session_id, event)
            if intent == "privilege_escalation":
                return await self._finalize(
                    session_id,
                    cmd,
                    intent,
                    current_dir,
                    "[sudo] password for shophub:\n# ",
                    0.1,
                )
            return await self._finalize(session_id, cmd, intent, current_dir, "", 0.05)

        elif action == "FAKE_VULNERABILITY":
            cmd_lower = cmd.lower()
            if "find" in cmd_lower and any(
                x in cmd_lower for x in [".key", "key", "secret", "credential"]
            ):
                fake_find = (
                    "/home/shophub/.ssh/id_rsa\n"
                    "/home/shophub/shophub/config/api_keys.json\n"
                    "/opt/secrets/database.key\n"
                    "/etc/shophub/stripe_secret.key"
                )
                return await self._finalize(
                    session_id, cmd, intent, current_dir, fake_find, 0.2
                )
            if "sudo" in cmd_lower and ("-l" in cmd_lower or "list" in cmd_lower):
                fake_sudo = (
                    "User shophub may run the following commands on shophub-server:\n"
                    "    (ALL) NOPASSWD: /usr/bin/systemctl restart shophub\n"
                    "    (ALL) NOPASSWD: /usr/bin/docker-compose\n"
                    "    (ALL) NOPASSWD: /bin/bash\n"
                    "    (root) /usr/bin/mysql"
                )
                return await self._finalize(
                    session_id, cmd, intent, current_dir, fake_sudo, 0.1
                )
            return await self._original_command_handler(session_id, event)

        elif action == "TERMINATE_SESSION":
            cmd_count = int(meta.get("cmd_count", 0) or 0)
            elapsed = float(meta.get("elapsed", 0.0) or 0.0)
            min_elapsed = BASELINE_CONFIG.get("quick_disconnect_threshold", 30)

            if cmd_count < 5 or elapsed < min_elapsed:
                print(
                    f"[Controller] Ignoring early TERMINATE_SESSION for {session_id} "
                    f"(cmd_count={cmd_count}, elapsed={elapsed:.2f}s)"
                )
                response = await self._original_command_handler(session_id, event)
                response["delay"] = max(response.get("delay", 0.0), 0.1)
                return response

            return {
                "response": "Connection to shophub-prod-01 closed by remote host.",
                "delay": 0.0,
                "disconnect": True,
            }

        return await self._original_command_handler(session_id, event)

    def end_session(self, session_id: str):
        if session_id in self.sessions:
            if self.rl_enabled:
                curr_state = extract_state(session_id, protocol="ssh")
                self._update_pending_rl(session_id, curr_state, terminal=True)
            print(f"[Controller] Session {session_id} ended")
            del self.sessions[session_id]
