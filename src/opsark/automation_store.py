"""Persist operator mode choices without granting an execution capability."""

import hashlib
import json
import sqlite3
from contextlib import closing
from datetime import UTC, datetime
from pathlib import Path

from pydantic import Field

from opsark.control_modes import MODE_CATALOG, ControlPolicy, Mode
from opsark.models import StrictModel


class ModeChange(StrictModel):
    mode: Mode
    expected_revision: int = Field(ge=0, strict=True)


class StaleModeError(ValueError):
    pass


class AutomationStore:
    def __init__(
        self,
        path: Path,
        policy: ControlPolicy,
        *,
        driver_scope: str | None = None,
        supplemental_scope: str | None = None,
    ):
        self.path = path
        self.policy = ControlPolicy.model_validate(policy.model_dump())
        # An absent opt-in preserves the existing deployment scope and mode revision.
        policy_json = json.dumps(
            self.policy.model_dump(
                mode="json", exclude={"automatic_ai"} if self.policy.automatic_ai is None else set()
            ),
            sort_keys=True,
        )
        if driver_scope is not None and (
            len(driver_scope) != 64 or any(c not in "0123456789abcdef" for c in driver_scope)
        ):
            raise ValueError("执行器范围摘要无效。")
        self.driver_scope = driver_scope
        if supplemental_scope is not None and (
            type(supplemental_scope) is not str
            or len(supplemental_scope) != 64
            or any(c not in "0123456789abcdef" for c in supplemental_scope)
        ):
            raise ValueError("附加执行通道范围摘要无效。")
        self.supplemental_scope = supplemental_scope
        self.sync_required = driver_scope is not None or supplemental_scope is not None
        scope_input = (
            "no-executor/v1\n" + policy_json
            if driver_scope is None
            else "ubuntu-apt/v1\n" + policy_json + "\n" + driver_scope
        )
        if supplemental_scope is not None:
            scope_input = json.dumps(
                {
                    "channel": "shared-mode/v1",
                    "existing_scope": scope_input,
                    "supplemental_scope": supplemental_scope,
                },
                sort_keys=True,
                separators=(",", ":"),
            )
        self.scope = hashlib.sha256(scope_input.encode()).hexdigest()
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        with closing(sqlite3.connect(path, timeout=5)) as connection, connection:
            connection.execute(
                "CREATE TABLE IF NOT EXISTS automation_mode ("
                "id INTEGER PRIMARY KEY CHECK(id=1),scope TEXT NOT NULL,mode TEXT NOT NULL,"
                "revision INTEGER NOT NULL,updated_at TEXT NOT NULL)"
            )
            columns = {row[1] for row in connection.execute("PRAGMA table_info(automation_mode)")}
            if "sync_revision" not in columns:
                connection.execute("ALTER TABLE automation_mode ADD COLUMN sync_revision INTEGER")
            if "sync_error" not in columns:
                connection.execute("ALTER TABLE automation_mode ADD COLUMN sync_error TEXT")
            if "sync_generation" not in columns:
                connection.execute(
                    "ALTER TABLE automation_mode ADD COLUMN "
                    "sync_generation INTEGER NOT NULL DEFAULT 0"
                )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS automation_audit ("
                "revision INTEGER PRIMARY KEY,mode TEXT NOT NULL,scope TEXT NOT NULL,"
                "created_at TEXT NOT NULL)"
            )
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute("SELECT scope, revision FROM automation_mode").fetchone()
            if row is None:
                self._write(connection, Mode.manual, 0)
            elif row[0] != self.scope:
                # New privileges, targets or a future driver require a fresh mode choice.
                self._write(connection, Mode.manual, row[1] + 1)
        path.chmod(0o600)

    def _write(self, connection: sqlite3.Connection, mode: Mode, revision: int) -> None:
        now = datetime.now(UTC).isoformat()
        connection.execute(
            "INSERT INTO automation_mode("
            "id,scope,mode,revision,updated_at,sync_revision,sync_error) "
            "VALUES(1,?,?,?,?,NULL,NULL) ON CONFLICT(id) DO UPDATE SET "
            "scope=excluded.scope,mode=excluded.mode,revision=excluded.revision,"
            "updated_at=excluded.updated_at,sync_revision=NULL,sync_error=NULL",
            (self.scope, mode.value, revision, now),
        )
        connection.execute(
            "INSERT INTO automation_audit VALUES(?,?,?,?)", (revision, mode.value, self.scope, now)
        )
        connection.execute(
            "DELETE FROM automation_audit WHERE revision IN (SELECT revision FROM "
            "automation_audit ORDER BY revision DESC LIMIT -1 OFFSET 1000)"
        )

    def status(self) -> dict:
        with closing(sqlite3.connect(self.path, timeout=5)) as connection:
            row = connection.execute(
                "SELECT scope,mode,revision,updated_at,sync_revision,sync_error,sync_generation "
                "FROM automation_mode WHERE id=1"
            ).fetchone()
        if row is None or row[0] != self.scope:
            raise StaleModeError("部署策略已变化，请重新加载控制端。")
        synchronized = not self.sync_required or row[4] == row[2] and row[5] is None
        available = self.driver_scope is not None and self.policy.enabled and synchronized
        grant = self.policy.automatic
        now = datetime.now(UTC)
        automatic = bool(
            self.driver_scope is not None
            and self.policy.enabled
            and grant
            and grant.enabled
            and grant.issued_at <= now < grant.expires_at
        )
        supported = ["assisted"] if self.driver_scope is not None else []
        if automatic:
            supported.append("automatic")
        if row[1] == "automatic" and not automatic:
            available = False
        if self.driver_scope is None:
            detail = "当前执行器尚未配置；已保存模式选择，不会据此执行修复。"
        elif not synchronized:
            detail = "模式尚未同步至本轮所需的登记服务器，已停止提交新修复任务。"
        elif not self.policy.enabled:
            detail = "修复入口已登记，但部署端执行策略未启用。"
        elif row[1] == "automatic" and not automatic:
            detail = "已保存自动模式，但没有当前有效的明确预授权，不会提交自动修复。"
        elif automatic:
            detail = (
                "已登记半自动执行和受限自动修复；自动任务仍需逐项通过窗口、证据、配额与暂停检查。"
            )
        else:
            detail = "已登记 Ubuntu 补丁执行器；半自动批准执行可用，自动修复需要单独的有效预授权。"
        return {
            "mode": Mode(row[1]).value,
            "revision": row[2],
            "updated_at": row[3],
            "modes": MODE_CATALOG,
            "policy": self.policy.model_dump(mode="json"),
            "execution_available": available,
            "supported_execution_modes": supported,
            "mode_sync_complete": synchronized,
            "mode_sync_error": row[5],
            "sync_generation": row[6],
            "detail": detail,
        }

    def mark_sync_pending(self, revision: int) -> int:
        if type(revision) is not int or revision < 0:
            raise ValueError("模式同步结果无效。")
        with closing(sqlite3.connect(self.path, timeout=5)) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT scope,revision,sync_generation FROM automation_mode WHERE id=1"
            ).fetchone()
            if row is None or row[0] != self.scope or row[1] != revision:
                raise StaleModeError("模式已改变，不能开始旧模式的同步。")
            if type(row[2]) is not int or not 0 <= row[2] < 2**63 - 1:
                raise StaleModeError("模式同步轮次无法核实。")
            generation = row[2] + 1
            connection.execute(
                "UPDATE automation_mode SET sync_revision=NULL,sync_error=?,sync_generation=? "
                "WHERE id=1",
                ("等待向登记服务器同步模式。", generation),
            )
            return generation

    def finish_sync(
        self, revision: int, error: str | None = None, *, expected_generation: int | None = None
    ) -> None:
        if (
            type(revision) is not int
            or revision < 0
            or error is not None
            and (not isinstance(error, str) or len(error) > 500)
        ):
            raise ValueError("模式同步结果无效。")
        if expected_generation is not None and (
            type(expected_generation) is not int or expected_generation < 0
        ):
            raise ValueError("模式同步轮次无效。")
        if self.supplemental_scope is not None and expected_generation is None:
            raise StaleModeError("附加通道同步必须绑定原轮次。")
        with closing(sqlite3.connect(self.path, timeout=5)) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT scope,revision,sync_generation FROM automation_mode WHERE id=1"
            ).fetchone()
            if (
                row is None
                or row[0] != self.scope
                or row[1] != revision
                or expected_generation is not None
                and row[2] != expected_generation
            ):
                raise StaleModeError("模式已改变，旧同步结果不能恢复执行能力。")
            connection.execute(
                "UPDATE automation_mode SET sync_revision=?,sync_error=? WHERE id=1",
                (revision if error is None else None, error),
            )

    def change_mode(self, request: ModeChange) -> dict:
        request = ModeChange.model_validate(request.model_dump())
        with closing(sqlite3.connect(self.path, timeout=5)) as connection, connection:
            connection.execute("BEGIN IMMEDIATE")
            row = connection.execute(
                "SELECT scope,mode,revision FROM automation_mode WHERE id=1"
            ).fetchone()
            if row is None or row[0] != self.scope or row[2] != request.expected_revision:
                raise StaleModeError("模式或部署策略已变化，请重新加载后再选择。")
            if row[1] != request.mode.value:
                self._write(connection, request.mode, row[2] + 1)
        return self.status()


def load_policy(path: Path | None) -> ControlPolicy:
    if path is None:
        return ControlPolicy()
    if path.is_symlink() or path.stat().st_size > 8192:
        raise ValueError("自动化策略需要有界的部署端普通文件。")
    return ControlPolicy.model_validate_json(path.read_bytes())
