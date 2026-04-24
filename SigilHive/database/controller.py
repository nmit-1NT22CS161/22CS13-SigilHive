import os
import re
import json
import importlib.util
import numpy as np
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, Optional
from llm_gen import generate_db_response_async
from kafka_manager import HoneypotKafkaManager
from rl_core.q_learning_agent import shared_rl_agent
from rl_core.state_extractor import extract_state
from rl_core.reward_calculator import calculate_reward
from rl_core.logging.structured_logger import log_interaction


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


# ── ShopHubDatabase (unchanged) ───────────────────────────────────────────────
class ShopHubDatabase:
    """Maintains ShopHub e-commerce database state"""

    def __init__(self, file_structure_path: Optional[Path] = None):
        self.file_structure_path = file_structure_path or _resolve_file_structure_path()
        self._file_mtime = 0.0
        self.databases = {}
        self.reload(force=True)
        self.current_db: Optional[str] = None

    def reload(self, force: bool = False):
        try:
            mtime = self.file_structure_path.stat().st_mtime
        except FileNotFoundError:
            return

        if not force and mtime <= self._file_mtime:
            return

        spec = importlib.util.spec_from_file_location(
            f"_db_fs_{int(mtime * 1000)}",
            self.file_structure_path,
        )
        if spec is None or spec.loader is None:
            return

        mod = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(mod)
        self.databases = getattr(mod, "DATABASES", {})
        self._file_mtime = mtime

    def create_database(self, db_name):
        if db_name.lower() not in self.databases:
            self.databases[db_name.lower()] = {"tables": {}}
            return True
        return False

    def drop_database(self, db_name):
        if db_name.lower() in self.databases and db_name.lower() not in [
            "information_schema",
            "mysql",
            "shophub",
            "shophub_logs",
        ]:
            del self.databases[db_name.lower()]
            return True
        return False

    def use_database(self, db_name):
        if db_name.lower() in self.databases:
            self.current_db = db_name.lower()
            return True
        return False

    def create_table(self, table_name, columns):
        if (
            self.current_db
            and table_name.lower() not in self.databases[self.current_db]["tables"]
        ):
            self.databases[self.current_db]["tables"][table_name.lower()] = {
                "columns": columns,
                "rows": [],
            }
            return True
        return False

    def drop_table(self, table_name):
        if (
            self.current_db
            and table_name.lower() in self.databases[self.current_db]["tables"]
        ):
            del self.databases[self.current_db]["tables"][table_name.lower()]
            return True
        return False

    def insert_into_table(self, table_name, values):
        if (
            self.current_db
            and table_name.lower() in self.databases[self.current_db]["tables"]
        ):
            self.databases[self.current_db]["tables"][table_name.lower()][
                "rows"
            ].append(values)
            return True
        return False

    def get_table_data(self, table_name, db_name=None):
        db = db_name.lower() if db_name else self.current_db
        if (
            db
            and db in self.databases
            and table_name.lower() in self.databases[db]["tables"]
        ):
            return self.databases[db]["tables"][table_name.lower()]
        return None

    def list_databases(self):
        return sorted(self.databases.keys())

    def list_tables(self, db_name=None):
        db = db_name.lower() if db_name else self.current_db
        if db and db in self.databases:
            return list(self.databases[db]["tables"].keys())
        return []

    def get_state_summary(self):
        summary = "ShopHub E-commerce Database System\n"
        summary += f"Current Database: {self.current_db}\n"
        summary += f"Available Databases: {', '.join(self.list_databases())}\n\n"
        if self.current_db:
            tables = self.list_tables()
            summary += f"Tables in '{self.current_db}': {len(tables)} tables\n"
            for table in tables[:10]:
                table_info = self.get_table_data(table)
                if table_info:
                    summary += (
                        f"  - {table}: {len(table_info.get('rows', []))} rows, "
                        f"{len(table_info.get('columns', []))} columns\n"
                        f"    Columns: {', '.join(table_info.get('columns', []))}\n"
                    )
        return summary


def extract_json_from_text(text):
    if not isinstance(text, str):
        return None
    text = text.strip()
    try:
        return json.loads(text)
    except Exception:
        pass
    cleaned = text.replace("```json", "").replace("```", "").strip()
    try:
        return json.loads(cleaned)
    except Exception:
        pass
    start, end = text.find("{"), text.rfind("}")
    if start != -1 and end != -1 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except Exception:
            pass
    return None


# ── ShopHubDBController ───────────────────────────────────────────────────────
class ShopHubDBController:
    """Intelligent controller for ShopHub MySQL honeypot"""

    NO_DB_ERROR = "ERROR 1046 (3D000): No database selected"

    def __init__(self):
        self.db_state = ShopHubDatabase()
        self.sessions = {}
        self.kafka_manager = HoneypotKafkaManager()

        self.rl_agent = shared_rl_agent
        self.rl_enabled = os.getenv("RL_ENABLED", "true").lower() == "true"
        print(f"[DBController] RL enabled: {self.rl_enabled}")

        # FIX 3: cross-honeypot context store
        # Maps session_id → list of {source, path/command, intent, ts}
        # Populated by Kafka handlers below; used to enrich LLM prompts.
        self._cross_context: Dict[str, list] = {}

        # FIX 3: register Kafka handlers so HTTP and SSH events are
        # actually consumed and influence DB responses.
        self.kafka_manager.register_handler("HTTPtoDB", self._on_http_event)
        self.kafka_manager.register_handler("SSHtoDB", self._on_ssh_event)

    def _reload_file_structure(self):
        self.db_state.reload()

    # ── FIX 3: cross-protocol Kafka handlers ─────────────────────────────────

    def _on_http_event(self, payload: dict) -> None:
        """
        Called for every event the HTTP honeypot publishes to HTTPtoDB.
        We record the path/intent so DB responses stay consistent with
        what the attacker already saw on the web service.
        """
        session_id = payload.get("session_id")
        if not session_id:
            return
        ctx = self._cross_context.setdefault(session_id, [])
        ctx.append(
            {
                "source": "http",
                "path": payload.get("path", ""),
                "intent": payload.get("intent", ""),
                "status": payload.get("status_code"),
                "ts": payload.get("timestamp"),
            }
        )
        # Cap at 20 events per session to avoid unbounded growth
        self._cross_context[session_id] = ctx[-20:]

    def _on_ssh_event(self, payload: dict) -> None:
        """
        Called for every event the SSH honeypot publishes to SSHtoDB.
        We record commands so the DB can reflect files the attacker
        already exfiltrated (e.g. if they cat'd .env over SSH, the DB
        acknowledges the same credentials).
        """
        session_id = payload.get("session_id")
        if not session_id:
            return
        ctx = self._cross_context.setdefault(session_id, [])
        ctx.append(
            {
                "source": "ssh",
                "command": payload.get("command", ""),
                "intent": payload.get("intent", ""),
                "ts": payload.get("timestamp"),
            }
        )
        self._cross_context[session_id] = ctx[-20:]

    def _get_cross_context_summary(self, session_id: str) -> str:
        """
        Return a brief text summary of sibling-protocol activity for
        *session_id*, injected into LLM prompts for consistency.
        Returns an empty string if there is no cross-protocol activity.
        """
        events = self._cross_context.get(session_id, [])
        if not events:
            return ""
        lines = ["Prior activity on sibling honeypots (for context consistency):"]
        for ev in events[-5:]:
            src = ev.get("source", "?")
            if src == "http":
                lines.append(
                    f"  HTTP {ev.get('path', '')} → {ev.get('intent', '')} (status {ev.get('status', '?')})"
                )
            elif src == "ssh":
                lines.append(f"  SSH cmd: {ev.get('command', '')[:60]}")
        return "\n".join(lines)

    # ── Query classification helpers (unchanged from original) ────────────────

    def _get_session(self, session_id):
        self._reload_file_structure()
        if session_id not in self.sessions:
            self.sessions[session_id] = {
                "query_history": [],
                "suspicious_count": 0,
                "failed_auth_attempts": 0,
                "username": None,
                "pending_rl": None,
            }
        return self.sessions[session_id]

    def _response_success(self, response: Dict) -> bool:
        text = str(response.get("response", "")).strip().upper()
        return not text.startswith("ERROR")

    def _update_pending_rl(
        self, session_id: str, curr_state: tuple, terminal: bool = False
    ):
        session = self.sessions.get(session_id)
        if not session:
            return

        pending = session.get("pending_rl")
        if not pending:
            return

        reward = calculate_reward(
            pending["state"], curr_state, protocol="database", terminal=terminal
        )
        self.rl_agent.update(pending["state"], pending["action"], reward, curr_state)
        session["pending_rl"] = None

        if terminal:
            self.rl_agent.save_q_table()

    def end_session(self, session_id: str):
        if session_id in self.sessions:
            if self.rl_enabled:
                curr_state = extract_state(session_id, protocol="database")
                self._update_pending_rl(session_id, curr_state, terminal=True)
            del self.sessions[session_id]

    def _classify_query(self, query):
        q_upper = query.upper().strip()
        if re.match(r"^\s*(DESCRIBE|DESC)\b", q_upper):
            return "describe"
        elif re.match(r"^\s*(SELECT|SHOW|EXPLAIN)\b", q_upper):
            return "read"
        elif re.match(r"^\s*(INSERT|UPDATE|DELETE)\b", q_upper):
            return "write"
        elif "CREATE DATABASE" in q_upper or "CREATE SCHEMA" in q_upper:
            return "create_db"
        elif "DROP DATABASE" in q_upper or "DROP SCHEMA" in q_upper:
            return "drop_db"
        elif "CREATE TABLE" in q_upper:
            return "create_table"
        elif "DROP TABLE" in q_upper:
            return "drop_table"
        elif "ALTER" in q_upper:
            return "alter"
        elif re.match(r"^\s*(GRANT|REVOKE)\b", q_upper):
            return "admin"
        elif "USE" in q_upper:
            return "use_db"
        else:
            return "other"

    def _is_suspicious(self, query):
        q_upper = query.upper()
        patterns = [
            "UNION SELECT",
            "OR 1=1",
            "AND 1=1",
            "' OR '",
            "'; DROP",
            "--",
            "LOAD_FILE",
            "INTO OUTFILE",
            "INTO DUMPFILE",
            "BENCHMARK(",
            "SLEEP(",
            "WAITFOR DELAY",
            "../",
            "password_hash",
            "authentication_string",
            "admin_users",
        ]
        return any(p in q_upper for p in patterns)

    # ── State-change parsers (unchanged) ─────────────────────────────────────

    def _parse_create_database(self, query):
        m = re.search(
            r'CREATE\s+(?:DATABASE|SCHEMA)\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"]?(\w+)[`"]?',
            query,
            re.IGNORECASE,
        )
        return m.group(1) if m else None

    def _parse_drop_database(self, query):
        m = re.search(
            r'DROP\s+(?:DATABASE|SCHEMA)\s+(?:IF\s+EXISTS\s+)?[`"]?(\w+)[`"]?',
            query,
            re.IGNORECASE,
        )
        return m.group(1) if m else None

    def _parse_use_database(self, query):
        m = re.search(r'USE\s+[`"]?(\w+)[`"]?', query, re.IGNORECASE)
        return m.group(1) if m else None

    def _parse_create_table(self, query):
        m = re.search(
            r'CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?[`"]?(\w+)[`"]?\s*\((.*?)\)',
            query,
            re.IGNORECASE | re.DOTALL,
        )
        if m:
            table_name = m.group(1)
            columns = []
            for col_def in m.group(2).split(","):
                col_name = col_def.strip().split()[0].strip('`"')
                if col_name.upper() not in [
                    "PRIMARY",
                    "KEY",
                    "FOREIGN",
                    "CONSTRAINT",
                    "INDEX",
                ]:
                    columns.append(col_name)
            return (table_name, columns)
        return None

    def _parse_drop_table(self, query):
        m = re.search(
            r'DROP\s+TABLE\s+(?:IF\s+EXISTS\s+)?[`"]?(\w+)[`"]?', query, re.IGNORECASE
        )
        return m.group(1) if m else None

    def _parse_insert(self, query):
        m = re.search(
            r'INSERT\s+INTO\s+[`"]?(\w+)[`"]?.*?VALUES\s*\((.*?)\)',
            query,
            re.IGNORECASE | re.DOTALL,
        )
        if m:
            values = [v.strip().strip("'\"") for v in m.group(2).split(",")]
            return (m.group(1), values)
        return None

    def _parse_select(self, query):
        m = re.search(r'FROM\s+[`"]?(\w+)[`"]?', query, re.IGNORECASE)
        return m.group(1) if m else None

    def _parse_select_details(self, query):
        m = re.search(
            r"SELECT\s+(.*?)\s+FROM\s+[`\"]?(\w+)[`\"]?",
            query,
            re.IGNORECASE | re.DOTALL,
        )
        if not m:
            return None, None

        raw_columns = m.group(1).strip()
        table_name = m.group(2)

        if raw_columns == "*":
            return table_name, ["*"]

        columns = []
        for col in raw_columns.split(","):
            cleaned = col.strip().strip("`\"")
            cleaned = re.split(r"\s+AS\s+", cleaned, flags=re.IGNORECASE)[0].strip()
            if "." in cleaned:
                cleaned = cleaned.split(".")[-1]
            columns.append(cleaned)
        return table_name, columns

    def _parse_describe(self, query):
        m = re.search(r'(?:DESCRIBE|DESC)\s+[`"]?(\w+)[`"]?', query, re.IGNORECASE)
        return m.group(1) if m else None

    def _execute_state_change(self, query, intent):
        if intent == "create_db":
            db_name = self._parse_create_database(query)
            if db_name:
                return (
                    (True, "Query OK, 1 row affected")
                    if self.db_state.create_database(db_name)
                    else (
                        False,
                        f"ERROR 1007 (HY000): Can't create database '{db_name}'; database exists",
                    )
                )
        elif intent == "drop_db":
            db_name = self._parse_drop_database(query)
            if db_name:
                return (
                    (True, "Query OK, 0 rows affected")
                    if self.db_state.drop_database(db_name)
                    else (
                        False,
                        f"ERROR 1008 (HY000): Can't drop database '{db_name}'; database doesn't exist",
                    )
                )
        elif intent == "use_db":
            db_name = self._parse_use_database(query)
            if db_name:
                return (
                    (True, "Database changed")
                    if self.db_state.use_database(db_name)
                    else (False, f"ERROR 1049 (42000): Unknown database '{db_name}'")
                )
        elif intent == "create_table":
            table_info = self._parse_create_table(query)
            if table_info:
                table_name, columns = table_info
                return (
                    (True, "Query OK, 0 rows affected")
                    if self.db_state.create_table(table_name, columns)
                    else (
                        False,
                        f"ERROR 1050 (42S01): Table '{table_name}' already exists",
                    )
                )
        elif intent == "drop_table":
            table_name = self._parse_drop_table(query)
            if table_name:
                return (
                    (True, "Query OK, 0 rows affected")
                    if self.db_state.drop_table(table_name)
                    else (False, f"ERROR 1051 (42S02): Unknown table '{table_name}'")
                )
        elif intent == "write":
            insert_info = self._parse_insert(query)
            if insert_info:
                table_name, values = insert_info
                return (
                    (True, "Query OK, 1 row affected")
                    if self.db_state.insert_into_table(table_name, values)
                    else (
                        False,
                        f"ERROR 1146 (42S02): Table '{table_name}' doesn't exist",
                    )
                )
        return False, "Query OK"

    async def _finalize_query(self, session_id, query, intent, response, delay):
        try:
            payload = {
                "session_id": session_id,
                "query": query,
                "intent": intent,
                "response": response,
                "delay": delay,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            self.kafka_manager.send(topic="DBtoHTTP", value=payload)
            self.kafka_manager.send(topic="DBtoSSH", value=payload)
            self.kafka_manager.send_dashboard(
                topic="honeypot-logs",
                value=payload,
                service="database",
                event_type=intent,
            )
        except Exception as e:
            print(f"[DBController] Kafka send error: {e}")
        return {"response": response, "delay": delay}

    async def _original_query_handler(self, session_id, event):
        query = event.get("query", "")
        intent = self._classify_query(query)

        if intent in [
            "create_db",
            "drop_db",
            "use_db",
            "create_table",
            "drop_table",
            "write",
        ]:
            _, message = self._execute_state_change(query, intent)
            return await self._finalize_query(session_id, query, intent, message, 0.05)

        if intent == "describe":
            table_name = self._parse_describe(query)
            if table_name:
                if not self.db_state.current_db:
                    return await self._finalize_query(
                        session_id, query, intent, self.NO_DB_ERROR, 0.0
                    )
                table_info = self.db_state.get_table_data(table_name)
                if table_info and "column_defs" in table_info:
                    response = {
                        "columns": ["Field", "Type", "Null", "Key", "Default", "Extra"],
                        "rows": table_info["column_defs"],
                    }
                    return await self._finalize_query(
                        session_id, query, intent, response, 0.0
                    )
                db = self.db_state.current_db or "shophub"
                return await self._finalize_query(
                    session_id,
                    query,
                    intent,
                    f"ERROR 1146 (42S02): Table '{db}.{table_name}' doesn't exist",
                    0.0,
                )

        if intent == "read":
            q_upper = query.upper()
            if "SHOW DATABASES" in q_upper or "SHOW SCHEMAS" in q_upper:
                return await self._finalize_query(
                    session_id,
                    query,
                    intent,
                    {
                        "columns": ["Database"],
                        "rows": [[db] for db in self.db_state.list_databases()],
                    },
                    0.0,
                )
            if "DATABASE()" in q_upper or "SCHEMA()" in q_upper:
                return await self._finalize_query(
                    session_id,
                    query,
                    intent,
                    {"columns": ["DATABASE()"], "rows": [[self.db_state.current_db]]},
                    0.0,
                )
            if "SHOW TABLES" in q_upper:
                if not self.db_state.current_db:
                    return await self._finalize_query(
                        session_id, query, intent, self.NO_DB_ERROR, 0.0
                    )
                tables = self.db_state.list_tables()
                colname = f"Tables_in_{self.db_state.current_db}"
                return await self._finalize_query(
                    session_id,
                    query,
                    intent,
                    {"columns": [colname], "rows": [[t] for t in tables]},
                    0.0,
                )

            table_name, selected_columns = self._parse_select_details(query)
            if table_name:
                if not self.db_state.current_db:
                    return await self._finalize_query(
                        session_id, query, intent, self.NO_DB_ERROR, 0.0
                    )
                table_info = self.db_state.get_table_data(table_name)
                if table_info:
                    columns = table_info.get("columns", [])
                    rows = table_info.get("rows", [])

                    projection = selected_columns or ["*"]
                    if projection != ["*"]:
                        unknown = [col for col in projection if col not in columns]
                        if unknown:
                            return await self._finalize_query(
                                session_id,
                                query,
                                intent,
                                f"ERROR 1054 (42S22): Unknown column '{unknown[0]}' in 'field list'",
                                0.0,
                            )
                        indexes = [columns.index(col) for col in projection]
                        rows = [[row[i] for i in indexes] for row in rows]
                        columns = projection

                    if not rows:
                        try:
                            db_context = self.db_state.get_state_summary()
                            cross_summary = self._get_cross_context_summary(session_id)
                            if cross_summary:
                                db_context = db_context + "\n" + cross_summary

                            llm_result = await generate_db_response_async(
                                query=query,
                                intent=intent,
                                db_context=db_context,
                                session_id=session_id,
                            )

                            if isinstance(llm_result, dict) and "columns" in llm_result and "rows" in llm_result:
                                llm_columns = [str(col) for col in llm_result.get("columns", [])]
                                llm_rows = llm_result.get("rows", [])

                                if projection == ["*"]:
                                    if llm_columns:
                                        columns = llm_columns
                                    rows = llm_rows
                                else:
                                    if all(col in llm_columns for col in projection):
                                        indexes = [llm_columns.index(col) for col in projection]
                                        rows = [[row[i] for i in indexes] for row in llm_rows]
                                        columns = projection
                        except Exception as e:
                            print(f"[DBController] LLM row generation error: {e}")

                    limit_match = re.search(r"LIMIT\s+(\d+)", query, re.IGNORECASE)
                    if limit_match:
                        rows = rows[: int(limit_match.group(1))]
                    return await self._finalize_query(
                        session_id,
                        query,
                        intent,
                        {"columns": columns, "rows": rows},
                        0.0,
                    )
                db = self.db_state.current_db or "shophub"
                return await self._finalize_query(
                    session_id,
                    query,
                    intent,
                    f"ERROR 1146 (42S02): Table '{db}.{table_name}' doesn't exist",
                    0.0,
                )

        # LLM fallback — also thread cross-context here
        try:
            db_context = self.db_state.get_state_summary()
            cross_summary = self._get_cross_context_summary(session_id)
            if cross_summary:
                db_context = db_context + "\n" + cross_summary
            fallback_raw = await generate_db_response_async(
                query=query, intent=intent, db_context=db_context
            )
            if isinstance(fallback_raw, str):
                json_data = extract_json_from_text(fallback_raw)
                fallback = json_data if json_data else {"text": fallback_raw}
            else:
                fallback = fallback_raw
        except Exception as e:
            print(f"[DBController] Fallback error: {e}")
            fallback = {"text": f"ERROR: {e}"}

        delay = 0.05 + float(np.random.rand()) * 0.2
        return await self._finalize_query(session_id, query, intent, fallback, delay)

    async def get_action_for_query(self, session_id, event):
        query = event.get("query", "")
        session = self._get_session(session_id)
        session["query_history"].append(query)
        session["query_history"] = session["query_history"][-50:]
        if event.get("username"):
            session["username"] = event.get("username")
        if self._is_suspicious(query):
            session["suspicious_count"] += 1

        intent = self._classify_query(query)
        state = extract_state(session_id, protocol="database")
        if self.rl_enabled:
            self._update_pending_rl(session_id, state)

        rl_action = None

        if self.rl_enabled:
            rl_action = self.rl_agent.select_action(state)
            response = await self._execute_rl_action(rl_action, session_id, event)
        else:
            response = await self._original_query_handler(session_id, event)

        log_interaction(
            session_id=session_id,
            protocol="database",
            input_data=query,
            metadata={
                "intent": intent,
                "suspicious": self._is_suspicious(query),
                "current_db": self.db_state.current_db,
                "response_action": rl_action or "BASELINE",
            },
            success=self._response_success(response),
        )

        if self.rl_enabled and rl_action is not None:
            session["pending_rl"] = {"state": state, "action": rl_action}

        return response

    async def _execute_rl_action(self, action, session_id, event):
        """Execute RL-selected action — unchanged from original."""
        query = event.get("query", "")
        intent = self._classify_query(query)
        query_upper = query.upper()

        if action == "REALISTIC_RESPONSE":
            return await self._original_query_handler(session_id, event)

        elif action == "DECEPTIVE_RESOURCE":
            query_lower = query.lower()
            if "user" in query_lower or "admin" in query_lower:
                fake_users = {
                    "columns": ["id", "username", "password_hash", "email", "role"],
                    "rows": [
                        [
                            1,
                            "admin",
                            "$2b$10$HONEYTOKEN_HASH_001",
                            "admin@shophub.com",
                            "superuser",
                        ],
                        [
                            2,
                            "dbadmin",
                            "$2b$10$HONEYTOKEN_HASH_002",
                            "dbadmin@shophub.com",
                            "admin",
                        ],
                    ],
                }
                return await self._finalize_query(
                    session_id, query, intent, fake_users, 0.1
                )
            if any(
                k in query_lower for k in ["credit", "card", "payment", "transaction"]
            ):
                fake_payments = {
                    "columns": ["id", "card_number", "cvv", "expiry", "cardholder"],
                    "rows": [
                        [1, "4532-HONEYTOKEN-001-1234", "123", "12/26", "John Doe"],
                        [2, "5425-HONEYTOKEN-002-5678", "456", "03/27", "Jane Smith"],
                    ],
                }
                return await self._finalize_query(
                    session_id, query, intent, fake_payments, 0.1
                )
            if any(
                k in query_lower
                for k in ["api", "key", "secret", "token", "credential"]
            ):
                fake_keys = {
                    "columns": ["id", "service", "api_key", "secret_key"],
                    "rows": [
                        [
                            1,
                            "stripe",
                            "pk_live_HONEYTOKEN_STRIPE_001",
                            "sk_live_HONEYTOKEN_STRIPE_SECRET",
                        ],
                        [
                            2,
                            "aws",
                            "AKIA_HONEYTOKEN_AWS_001",
                            "wJalrXUtn_HONEYTOKEN_AWS_SECRET",
                        ],
                    ],
                }
                return await self._finalize_query(
                    session_id, query, intent, fake_keys, 0.1
                )
            return await self._original_query_handler(session_id, event)

        elif action == "RESPONSE_DELAY":
            response = await self._original_query_handler(session_id, event)
            response["delay"] = response.get("delay", 0.0) + float(
                np.random.uniform(0.5, 2.0)
            )
            return response

        elif action == "MISLEADING_SUCCESS":
            if intent in ["write", "create_table", "drop_table", "alter"]:
                return await self._finalize_query(
                    session_id, query, intent, "Query OK, 1 row affected", 0.05
                )
            return await self._original_query_handler(session_id, event)

        elif action == "FAKE_VULNERABILITY":
            query_lower = query.lower()
            # Keep schema enumeration truthful so SHOW TABLES, DESC and SELECT
            # agree with one another across a session.
            if "information_schema" in query_lower or "show tables" in query_lower:
                return await self._original_query_handler(session_id, event)
            if "mysql.user" in query_lower:
                fake_mysql_users = {
                    "columns": ["user", "host", "authentication_string"],
                    "rows": [
                        ["root", "localhost", "*HONEYTOKEN_MYSQL_ROOT_HASH"],
                        ["shophub_app", "%", "*HONEYTOKEN_MYSQL_APP_HASH"],
                    ],
                }
                return await self._finalize_query(
                    session_id, query, intent, fake_mysql_users, 0.1
                )
            return await self._original_query_handler(session_id, event)

        elif action == "TERMINATE_SESSION":
            # Abrupt disconnects during metadata exploration feel broken and cause
            # client reconnect loops. Reserve termination for more invasive queries.
            if intent in {"describe", "use_db"} or "SHOW TABLES" in query_upper:
                response = await self._original_query_handler(session_id, event)
                response["delay"] = max(response.get("delay", 0.0), 0.05)
                return response

            if len(self._get_session(session_id).get("query_history", [])) < 5:
                response = await self._original_query_handler(session_id, event)
                response["delay"] = max(response.get("delay", 0.0), 0.1)
                return response

            return {
                "response": "ERROR 2013 (HY000): Lost connection to MySQL server during query",
                "delay": 0.0,
                "disconnect": True,
            }

        return await self._original_query_handler(session_id, event)
