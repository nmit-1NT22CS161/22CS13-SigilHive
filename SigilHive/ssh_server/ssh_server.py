import asyncio
import asyncssh
import os
import time
import uuid
from datetime import datetime, timezone
from dotenv import load_dotenv
from controller import Controller
from kafka_manager import HoneypotKafkaManager

# Load environment variables from .env file
load_dotenv()

HOST = "0.0.0.0"
PORT = int(os.getenv("PORT", "2223"))

# Configure valid credentials
VALID_USERNAME = os.getenv("SSH_USERNAME", "shophub")
VALID_PASSWORD = os.getenv("SSH_PASSWORD", "ShopHub121!")

controller = Controller(persona="shophub-production-server")


class HoneypotSession(asyncssh.SSHServerSession):
    def __init__(self, session_id):
        super().__init__()
        self._chan = None
        self.session_id = session_id
        self._input = ""
        self.start_time = time.time()
        self.cmd_count = 0
        self._closed = False
        self.current_dir = "~"
        self.username = "shophub"
        self.hostname = "shophub-prod-01"
        self._pending_tasks = set()
        self._banner_sent = False
        self._banner_attempts = 0
        self._command_lock = asyncio.Lock()

    def _mark_closed(self):
        self._closed = True

    def _safe_write(self, text: str) -> bool:
        """Write to the SSH channel only while it is still usable."""
        if self._closed or not self._chan:
            return False
        try:
            self._chan.write(str(text))
            return True
        except Exception as exc:
            print(
                f"[honeypot][{self.session_id}] write deferred/failed: {exc}",
                flush=True,
            )
            return False

    def _close_channel(self, exit_status: int = 0):
        """Close the SSH channel without raising if the client already left."""
        if self._closed or not self._chan:
            return
        self._mark_closed()
        try:
            self._chan.exit(exit_status)
        except Exception:
            pass
        try:
            self._chan.close()
        except Exception:
            pass

    def connection_made(self, chan):
        self._chan = chan
        print(f"[honeypot][{self.session_id}] connection established")

    def _write_prompt(self):
        """Write a realistic shell prompt"""
        prompt = (
            f"\033[32m{self.username}@{self.hostname}\033[0m:"
            f"\033[34m{self.current_dir}\033[0m$ "
        )
        self._safe_write(prompt)

    def _schedule_banner(self, delay: float = 0.05):
        loop = asyncio.get_running_loop()
        loop.call_later(delay, self._send_banner_if_ready)

    def _send_banner_if_ready(self):
        if self._closed or not self._chan or self._banner_sent:
            return

        self._banner_attempts += 1
        banner = (
            "\r\n"
            "===============================================\r\n"
            "   Welcome to ShopHub Production Server\r\n"
            "   WARNING: Unauthorized access is prohibited\r\n"
            "===============================================\r\n"
            f"ShopHub v2.3.1 - Last login: "
            f"{datetime.now().strftime('%a %b %d %H:%M:%S %Y')} from 10.0.2.15\r\n"
            "\r\n"
        )

        if self._safe_write(banner):
            self._banner_sent = True
            self._write_prompt()
            return

        if self._banner_attempts < 6 and not self._closed:
            self._schedule_banner(0.1)

    def _normalize_path(self, path: str) -> str:
        """Normalize a path relative to current directory"""
        path = (path or "").strip()

        if path == "" or path == ".":
            return self.current_dir

        if path.startswith("/"):
            if path == "/":
                return "/"
            if path.startswith("/home/shophub"):
                rel_path = path.replace("/home/shophub", "~", 1)
                if rel_path == "~":
                    return "~"
                path = rel_path
            else:
                return path.rstrip("/")

        if path.startswith("~"):
            if path == "~":
                return "~"
            base_parts = []
            raw_parts = path[2:].split("/") if path.startswith("~/") else []
        else:
            if self.current_dir == "~":
                base_parts = []
            elif self.current_dir.startswith("~/"):
                base_parts = [p for p in self.current_dir[2:].split("/") if p]
            else:
                return path.rstrip("/")
            raw_parts = path.split("/")

        parts = list(base_parts)
        for part in raw_parts:
            if part in ("", "."):
                continue
            if part == "..":
                if parts:
                    parts.pop()
                continue
            parts.append(part)

        return "~" if not parts else "~/" + "/".join(parts)

    def _get_parent_dir(self, path: str) -> str:
        """Get parent directory of given path"""
        if path == "~" or path == "/" or path == "/home/shophub":
            return "~"

        path = path.rstrip("/")

        if path.startswith("~/"):
            parts = path[2:].split("/")
            if len(parts) <= 1:
                return "~"
            return "~/" + "/".join(parts[:-1])

        if path.startswith("/"):
            parts = path[1:].split("/")
            if len(parts) <= 1:
                return "/"
            return "/" + "/".join(parts[:-1])

        return "~"

    def _directory_exists(self, path: str) -> bool:
        """Check if a directory exists in our structure"""
        controller._reload_file_structure()
        normalized = self._normalize_path(path)
        if normalized in ("~", "/home/shophub"):
            return True
        if normalized in controller.file_structure:
            return True
        if not normalized.startswith("~") and normalized.startswith("/home/shophub/"):
            alt = normalized.replace("/home/shophub", "~", 1)
            return alt in controller.file_structure
        if not normalized.startswith("~"):
            alt = f"~/{normalized.lstrip('/')}"
            return alt in controller.file_structure
        return False

    def data_received(self, data, datatype):
        """Handle incoming data from SSH client"""
        if self._closed:
            return

        self._input += data

        while "\n" in self._input or "\r" in self._input:
            if self._closed:
                return

            if "\r\n" in self._input:
                line, self._input = self._input.split("\r\n", 1)
            elif "\n" in self._input:
                line, self._input = self._input.split("\n", 1)
            elif "\r" in self._input:
                line, self._input = self._input.split("\r", 1)
            else:
                break

            cmd = line.strip()

            if cmd.lower() in ("exit", "logout", "quit"):
                self._safe_write("\nGoodbye from ShopHub!\n")
                self._close_channel(0)
                return

            if cmd == "":
                try:
                    self._write_prompt()
                except Exception:
                    pass
                continue

            if cmd.startswith("cd ") or cmd == "cd":
                self._handle_cd_command(cmd)
                continue

            self.cmd_count += 1
            task = asyncio.create_task(self.handle_command(cmd))
            self._pending_tasks.add(task)
            task.add_done_callback(self._pending_tasks.discard)

    def _handle_cd_command(self, cmd: str):
        """Handle cd command with validation"""
        parts = cmd.split(maxsplit=1)

        if len(parts) == 1 or (len(parts) > 1 and parts[1] == "~"):
            self.current_dir = "~"
        elif len(parts) > 1 and parts[1] == "..":
            self.current_dir = self._get_parent_dir(self.current_dir)
        elif len(parts) > 1 and parts[1] == ".":
            pass
        elif len(parts) > 1 and parts[1] == "/":
            self.current_dir = "~"
        else:
            target_path = self._normalize_path(parts[1])
            if self._directory_exists(target_path):
                self.current_dir = target_path
            else:
                self._safe_write(f"bash: cd: {parts[1]}: No such file or directory\n")
                self._write_prompt()
                return

        print(f"[honeypot][{self.session_id}] cd -> {self.current_dir}")
        self._write_prompt()

    async def handle_command(self, cmd: str):
        """Handle commands asynchronously"""
        if self._closed or not self._chan:
            return

        async with self._command_lock:
            event = {
                "session_id": self.session_id,
                "type": "command",
                "command": cmd,
                "current_dir": self.current_dir,
                "ts": datetime.now(timezone.utc).isoformat(),
                "cmd_count": self.cmd_count,
                "elapsed": time.time() - self.start_time,
            }

            try:
                action = await controller.get_action_for_session(self.session_id, event)
            except Exception as e:
                print(f"[honeypot][{self.session_id}] controller error: {e}")
                cmd_parts = cmd.split()
                base = cmd_parts[0] if cmd_parts else "unknown"
                action = {
                    "response": f"bash: {base}: command not found",
                    "delay": 0.05,
                }

            delay = float(action.get("delay", 0.0) or 0.0)
            if delay > 0:
                try:
                    await asyncio.sleep(delay)
                except asyncio.CancelledError:
                    return

            if self._closed or not self._chan:
                return

            response_text = action.get("response", "") or ""

            if response_text and not self._safe_write(str(response_text)):
                return
            if response_text and not str(response_text).endswith("\n"):
                if not self._safe_write("\n"):
                    return

            if action.get("disconnect"):
                print(f"[honeypot][{self.session_id}] controller requested disconnect")
                self._close_channel(0)
                return

            self._write_prompt()

    def eof_received(self):
        print(f"[honeypot][{self.session_id}] EOF received")
        return True

    def break_received(self, msec):
        print(f"[honeypot][{self.session_id}] break received (Ctrl+C)")
        return True

    def signal_received(self, signal):
        print(f"[honeypot][{self.session_id}] signal received: {signal}")

    def session_started(self):
        print(f"[honeypot][{self.session_id}] session started")
        if self._banner_sent:
            return
        try:
            self._schedule_banner()
        except Exception as e:
            print(f"[honeypot][{self.session_id}] error in session_started: {e}")

    def terminal_size_changed(self, width, height, pixwidth, pixheight):
        print(f"[honeypot][{self.session_id}] terminal resized: {width}x{height}")

    def pty_requested(self, *args, **kwargs):
        """Accept any pty_requested signature"""
        try:
            if len(args) >= 1:
                term = args[0]
            else:
                term = kwargs.get("term_type", kwargs.get("term", "<unknown>"))
            width = args[1] if len(args) >= 2 else kwargs.get("width", 80)
            height = args[2] if len(args) >= 3 else kwargs.get("height", 24)
            print(
                f"[honeypot][{self.session_id}] pty requested: term={term}, size={width}x{height}"
            )
        except Exception:
            print(f"[honeypot][{self.session_id}] pty requested (could not parse args)")
        return True

    def shell_requested(self):
        """Handle shell request from client"""
        print(f"[honeypot][{self.session_id}] shell requested")
        return True

    def connection_lost(self, exc):
        """Called when SSH connection is lost"""
        self._mark_closed()
        for task in list(self._pending_tasks):
            task.cancel()
        self._pending_tasks.clear()
        duration = time.time() - self.start_time
        print(f"[honeypot][{self.session_id}] connection closed after {duration:.2f}s")

        try:
            controller.end_session(self.session_id)
        except Exception as e:
            print(f"[honeypot][{self.session_id}] error ending session: {e}")

        if exc:
            print(f"[honeypot][{self.session_id}] connection error: {exc}")


class HoneypotServer(asyncssh.SSHServer):
    """Custom SSH server class that creates sessions"""

    def connection_made(self, conn):
        self.conn_id = str(uuid.uuid4())[:8]
        print(
            f"[honeypot][{self.conn_id}] new SSH connection established from {conn.get_extra_info('peername')}"
        )

    def connection_lost(self, exc):
        if exc:
            print(f"[honeypot][{self.conn_id}] connection error: {exc}")
        else:
            print(f"[honeypot][{self.conn_id}] connection closed cleanly")

    def begin_auth(self, username):
        print(
            f"[honeypot][{self.conn_id}] authentication attempt for user '{username}'"
        )
        return True

    def password_auth_supported(self):
        return True

    def kbdint_auth_supported(self):
        return False

    def public_key_auth_supported(self):
        return False

    def validate_password(self, username, password):
        print(f"[honeypot][{self.conn_id}] login attempt: {username}:{password}")

        is_valid = username == VALID_USERNAME and password == VALID_PASSWORD

        if is_valid:
            print(
                f"[honeypot][{self.conn_id}] authentication successful for '{username}'"
            )
        else:
            print(
                f"[honeypot][{self.conn_id}] authentication failed for '{username}'"
            )

        return is_valid

    def session_requested(self):
        session_id = str(uuid.uuid4())[:8]
        return HoneypotSession(session_id)


def ensure_host_key(path="ssh_host_key"):
    """Create a RSA host key file if it doesn't exist"""
    if os.path.exists(path):
        return
    try:
        print("[honeypot] generating ssh host key...")
        key = asyncssh.generate_private_key("ssh-rsa")
        with open(path, "wb") as f:
            f.write(key.export_private_key())
        pub = key.export_public_key()
        with open(path + ".pub", "wb") as f:
            f.write(pub)
        try:
            os.chmod(path, 0o600)
        except OSError:
            pass
        print("[honeypot] ssh host key generated")
    except Exception as e:
        print(f"[honeypot] failed to generate host key: {e}")


async def start_server():
    """Start the honeypot SSH server"""
    print(f"[honeypot] starting SSH honeypot on {HOST}:{PORT} ...")
    print(f"[honeypot] valid credentials: {VALID_USERNAME}:{VALID_PASSWORD}")

    ensure_host_key("ssh_host_key")

    try:
        await asyncssh.create_server(
            HoneypotServer,
            HOST,
            PORT,
            server_host_keys=["ssh_host_key"],
        )
        print(f"[honeypot] listening on {HOST}:{PORT}")
        await asyncio.Future()
    except (OSError, asyncssh.Error) as exc:
        print(f"[honeypot] server failed to start: {exc}")


async def consumer():
    kafka_manager = HoneypotKafkaManager()
    topics = ["HTTPtoSSH", "DBtoSSH"]
    kafka_manager.subscribe(topics)
    await kafka_manager.consume()


async def start():
    await asyncio.gather(
        start_server(),
        consumer(),
    )


if __name__ == "__main__":
    try:
        asyncio.run(start())
    except KeyboardInterrupt:
        print("\n[honeypot] stopped by user")
    except Exception as e:
        print(f"[honeypot] error: {e}")
