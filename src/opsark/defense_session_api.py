"""Authenticated fixed single-session controls and small local history views."""

from __future__ import annotations

import sqlite3
from typing import Annotated, Literal, Protocol

from fastapi import APIRouter, FastAPI, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import Field, model_validator

from opsark.defense_models import DefenseModel, Digest, Identifier
from opsark.defense_policy import HostId
from opsark.defense_session_models import SessionRecord
from opsark.defense_store import DefenseConflict

TERMINAL = frozenset({"completed", "stopped", "expired", "reconciliation_only"})


class SessionStart(DefenseModel):
    cursor_request_id: Identifier
    session_ref: Identifier
    expected_mode_revision: int = Field(ge=0, le=2**31 - 2)
    confirm_session: Literal[True]

    @model_validator(mode="before")
    @classmethod
    def explicit(cls, value):
        if type(value) is not dict or value.get("confirm_session") is not True:
            raise ValueError("The original single session needs explicit confirmation")
        return value


class SessionStop(DefenseModel):
    expected_declaration_sha256: Digest
    confirm_stop: Literal[True]

    @model_validator(mode="before")
    @classmethod
    def explicit(cls, value):
        if type(value) is not dict or value.get("confirm_stop") is not True:
            raise ValueError("Stopping this original session needs explicit confirmation")
        return value


class SessionCoordinator(Protocol):
    def status(self) -> dict: ...
    def owned_session_refs(self) -> tuple[str, ...]: ...
    def start(
        self, host_id: str, cursor_rid: str, *, session_ref: str, expected_mode_revision: int
    ) -> SessionRecord: ...
    def get(self, session_ref: str) -> SessionRecord: ...
    def ai_receipt(self, host_id: str, session_ref: str) -> dict: ...
    def list(self, host_id: str, *, after_sequence: int = 0, limit: int = 20) -> dict: ...
    def stop(self, session_ref: str | None = None): ...


class SessionDispatcher(Protocol):
    enabled: bool

    def status(self) -> dict: ...
    def wake(self) -> None: ...


def session_view(record: SessionRecord, owned: tuple[str, ...], *, sequence=None):
    """No source, raw receipt, owner, provider settings or exception text leaves here."""
    declaration = record.declaration
    reference = declaration.session_ref
    return {
        "v": 1,
        "sequence": sequence,
        "host_id": declaration.runtime.context.host_id,
        "session_ref": reference,
        "cursor_request_id": declaration.cursor_rid,
        "action_request_id": None if record.action is None else record.action.rid,
        "declaration_sha256": record.declaration_sha256,
        "phase": record.phase,
        "effective_phase": record.effective_phase,
        "created_at": record.created_at,
        "updated_at": record.updated_at,
        "controller_deadline_at": declaration.controller_deadline_at,
        "mode_revision": declaration.runtime.mode.revision,
        "requires_ai": declaration.runtime.requires_ai,
        "max_actions_per_session": 1,
        "max_ai_intents": 1,
        "business_verdict": "pending",
        "stop_reason": record.stop_reason,
        "owned_by_current_boot": reference in owned,
        "can_stop": reference in owned and record.phase not in TERMINAL,
    }


def register_defense_session_routes(
    app: FastAPI, coordinator: SessionCoordinator, dispatcher: SessionDispatcher, protected: list
):
    class SessionRoute(APIRoute):
        def get_route_handler(self):
            original = super().get_route_handler()

            async def bounded(request):
                try:
                    response = await original(request)
                    response.headers["Cache-Control"] = "no-store"
                    return response
                except RequestValidationError:
                    raise HTTPException(422, "单次会话请求不符合固定约定。") from None

            return bounded

    router = APIRouter(dependencies=protected, route_class=SessionRoute)

    def guarded(call):
        try:
            return call()
        except DefenseConflict:
            raise HTTPException(409, "单次会话状态或授权无法核实。") from None
        except (ValueError, OSError, RuntimeError, sqlite3.Error, KeyError):
            raise HTTPException(503, "单次会话记录暂时不可用。") from None

    def original(host_id, session_ref):
        record = coordinator.get(session_ref)
        if record.declaration.runtime.context.host_id != host_id:
            raise DefenseConflict("Session belongs to another original host")
        return record

    @router.get("/api/ssh-defense/sessions/status")
    def status():
        def read():
            current = coordinator.status()
            return {
                "v": 1,
                **dispatcher.status(),
                "session_only": True,
                "continuous_execution": False,
                "max_actions_per_session": 1,
                "owned_sessions": current["owned_sessions"],
                "mutation_owner": current["mutation_owner"],
            }

        return guarded(read)

    @router.get("/api/hosts/{host_id}/ssh-defense/sessions")
    def history(
        host_id: HostId,
        after_sequence: Annotated[int, Query(ge=0, le=2**63 - 1)] = 0,
        limit: Annotated[int, Query(ge=1, le=20)] = 20,
    ):
        def read():
            page = coordinator.list(host_id, after_sequence=after_sequence, limit=limit)
            owned = coordinator.owned_session_refs()
            return {
                "v": 1,
                "host_id": host_id,
                "sessions": [
                    session_view(row["record"], owned, sequence=row["sequence"])
                    for row in page["sessions"]
                ],
                "next_after_sequence": page["next_after_sequence"],
            }

        return guarded(read)

    @router.get("/api/hosts/{host_id}/ssh-defense/sessions/{session_ref}")
    def get(host_id: HostId, session_ref: Identifier):
        return guarded(
            lambda: session_view(original(host_id, session_ref), coordinator.owned_session_refs())
        )

    @router.get("/api/hosts/{host_id}/ssh-defense/sessions/{session_ref}/ai-receipt")
    def ai_receipt(host_id: HostId, session_ref: Identifier):
        return guarded(lambda: coordinator.ai_receipt(host_id, session_ref))

    @router.post("/api/hosts/{host_id}/ssh-defense/sessions")
    def start(host_id: HostId, body: SessionStart):
        if not dispatcher.enabled:
            raise HTTPException(403, "单次会话需由部署端明确启用。")

        def begin():
            record = coordinator.start(
                host_id,
                body.cursor_request_id,
                session_ref=body.session_ref,
                expected_mode_revision=body.expected_mode_revision,
            )
            dispatcher.wake()
            return session_view(record, coordinator.owned_session_refs())

        return guarded(begin)

    @router.post("/api/hosts/{host_id}/ssh-defense/sessions/{session_ref}/stop")
    def stop(host_id: HostId, session_ref: Identifier, body: SessionStop):
        def halt():
            record = original(host_id, session_ref)
            if record.declaration_sha256 != body.expected_declaration_sha256:
                raise DefenseConflict("Original session declaration changed")
            coordinator.stop(session_ref)
            return session_view(original(host_id, session_ref), coordinator.owned_session_refs())

        return guarded(halt)

    app.include_router(router)
