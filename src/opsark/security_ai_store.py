"""Persist only validated model advice, bound to its confirmed evidence input."""

import json
import re
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path


class SecurityAIStore:
    def __init__(self, path: Path):
        self.path = path
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with closing(sqlite3.connect(path, timeout=5)) as connection, connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS security_analysis ("
                "alert_id TEXT PRIMARY KEY,input_digest TEXT NOT NULL,"
                "created_at TEXT NOT NULL,payload TEXT NOT NULL)"
            )
        path.chmod(0o600)

    def save(self, alert_id: str, input_digest: str, payload: dict) -> None:
        if not all(re.fullmatch(r"[0-9a-f]{64}", value) for value in (alert_id, input_digest)):
            raise ValueError("Invalid advice binding")
        if payload.get("status") != "completed" or payload.get("actions_executable") is not False:
            raise ValueError("Only completed non-executable advice can be persisted")
        text = json.dumps(payload, ensure_ascii=False, separators=(",", ":"))
        if len(text.encode()) > 32768:
            raise ValueError("Advice exceeded storage budget")
        with closing(sqlite3.connect(self.path, timeout=5)) as connection, connection:
            connection.execute(
                "INSERT INTO security_analysis VALUES(?,?,?,?) ON CONFLICT(alert_id) DO UPDATE SET "
                "input_digest=excluded.input_digest,created_at=excluded.created_at,"
                "payload=excluded.payload",
                (alert_id, input_digest, datetime.now(UTC).isoformat(), text),
            )
            connection.execute(
                "DELETE FROM security_analysis WHERE alert_id IN (SELECT alert_id FROM "
                "security_analysis ORDER BY created_at DESC LIMIT -1 OFFSET 1000)"
            )

    def get(self, alert_id: str) -> dict | None:
        with closing(sqlite3.connect(self.path, timeout=5)) as connection:
            connection.row_factory = sqlite3.Row
            row = connection.execute(
                "SELECT * FROM security_analysis WHERE alert_id=?", (alert_id,)
            ).fetchone()
        if row is None:
            return None
        return {
            "input_digest": row["input_digest"],
            "created_at": row["created_at"],
            "analysis": json.loads(row["payload"]),
        }
