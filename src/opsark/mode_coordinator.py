"""One durable desired mode and a shared pending boundary across execution channels."""

import hashlib
import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from threading import Lock

from opsark.automation_store import AutomationStore, ModeChange, StaleModeError
from opsark.patch_api import ModeSynchronizationError


@dataclass(frozen=True)
class ModeSnapshot:
    scope: str
    mode: str
    revision: int
    sync_generation: int = 0

    @property
    def wire_revision(self) -> int:
        if not 0 <= self.revision <= 2**31 - 2:
            raise ValueError("模式修订无法映射至防护协议。")
        return self.revision + 1


@dataclass(frozen=True)
class ModeParticipant:
    name: str
    scope: str
    synchronize: Callable[[ModeSnapshot], bool] = field(repr=False, compare=False)

    def __post_init__(self):
        if (
            type(self.name) is not str
            or re.fullmatch(r"[a-z][a-z0-9-]{0,39}", self.name) is None
            or type(self.scope) is not str
            or re.fullmatch(r"[0-9a-f]{64}", self.scope) is None
            or not callable(self.synchronize)
        ):
            raise ValueError("模式同步通道登记无效。")


def supplemental_scope(participants: tuple[ModeParticipant, ...]) -> str | None:
    """The APT scope keeps its existing binding; added channels receive a new binding."""
    extra = {p.name: p.scope for p in participants if p.name != "ubuntu-apt"}
    if len({p.name for p in participants}) != len(participants):
        raise ValueError("模式同步通道不能重复。")
    if not extra:
        return None
    raw = json.dumps(extra, sort_keys=True, separators=(",", ":")).encode("ascii")
    return hashlib.sha256(b"mode-participants/v1\n" + raw).hexdigest()


class ModeCoordinator:
    def __init__(
        self,
        automation: AutomationStore,
        mode_lock: Lock,
        participants: tuple[ModeParticipant, ...],
    ):
        self.automation = automation
        self.mode_lock = mode_lock
        self.participants = tuple(participants)
        if supplemental_scope(self.participants) != automation.supplemental_scope:
            raise ValueError("模式同步通道与持久范围不一致。")
        primary = [p for p in self.participants if p.name == "ubuntu-apt"]
        if (
            automation.driver_scope is None
            and primary
            or automation.driver_scope is not None
            and (len(primary) != 1 or primary[0].scope != automation.driver_scope)
        ):
            raise ValueError("补丁通道必须保持其独立范围并参与全局同步。")
        self.scope = automation.scope

    def _snapshot(self) -> ModeSnapshot:
        status = self.automation.status()
        if self.automation.scope != self.scope:
            raise StaleModeError("模式同步部署范围已改变。")
        return ModeSnapshot(
            self.scope, status["mode"], status["revision"], status["sync_generation"]
        )

    def status(self) -> dict:
        result = self.automation.status()
        return {**result, "sync_channels": [p.name for p in self.participants]}

    def _begin(self, body: ModeChange | None) -> ModeSnapshot:
        with self.mode_lock:
            if body is not None:
                self.automation.change_mode(body)
            snapshot = self._snapshot()
            # Fail locally before contacting any defense participant at an unmappable revision.
            if self.automation.supplemental_scope is not None and snapshot.wire_revision < 1:
                raise ValueError("防护协议模式修订无效。")
            generation = self.automation.mark_sync_pending(snapshot.revision)
            return ModeSnapshot(snapshot.scope, snapshot.mode, snapshot.revision, generation)

    def _synchronize(self, snapshot: ModeSnapshot) -> dict:
        failed = False
        for participant in self.participants:
            try:
                # Each participant verifies its complete native ACK and owns durable per-RID state.
                if participant.synchronize(snapshot) is not True:
                    failed = True
            except Exception:
                failed = True
        with self.mode_lock:
            if self._snapshot() != snapshot:
                raise StaleModeError("旧模式同步结果不能确认新的模式修订。")
            self.automation.finish_sync(
                snapshot.revision,
                "至少一个执行通道未确认当前模式，已停止新动作。" if failed else None,
                expected_generation=snapshot.sync_generation,
            )
            result = self.status()
        if failed:
            raise ModeSynchronizationError("执行通道模式同步未完成，已停止新动作。")
        return result

    def sync_mode(self) -> dict:
        return self._synchronize(self._begin(None))

    def change_mode(self, body: ModeChange) -> dict:
        return self._synchronize(self._begin(body))
