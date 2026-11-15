"""Reference-only HTTP interface for independently collected defense rechecks."""

from __future__ import annotations

import sqlite3
from typing import Annotated, Literal, Protocol

from fastapi import APIRouter, FastAPI, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.responses import Response
from fastapi.routing import APIRoute
from pydantic import model_validator

from opsark.defense_models import DefenseModel, Digest, Identifier
from opsark.defense_policy import HostId
from opsark.defense_store import DefenseConflict


class DefenseRecheckRequest(DefenseModel):
    run_ref: Identifier
    expected_manifest_sha256: Digest
    expected_profile_sha256: Digest
    confirm_recheck: Literal[True]

    @model_validator(mode="before")
    @classmethod
    def exact_confirmation(cls, value):
        if type(value) is not dict or value.get("confirm_recheck") is not True:
            raise ValueError("Explicit recheck confirmation is required")
        return value


class DefenseRecheckInterrupt(DefenseModel):
    expected_declaration_sha256: Digest
    confirm_interrupt: Literal[True]

    @model_validator(mode="before")
    @classmethod
    def exact_confirmation(cls, value):
        if type(value) is not dict or value.get("confirm_interrupt") is not True:
            raise ValueError("Explicit interrupt confirmation is required")
        return value


class DefenseRecheckRoutes(Protocol):
    def start(self, host_id: str, rid: str, body: DefenseRecheckRequest) -> dict: ...
    def get(self, host_id: str, rid: str, run_ref: str) -> dict: ...
    def interrupt(
        self, host_id: str, rid: str, run_ref: str, body: DefenseRecheckInterrupt
    ) -> dict: ...
    def list(self, host_id: str, rid: str, *, after_sequence: int = 0, limit: int = 20) -> dict: ...
    def legacy_list(
        self, host_id: str, rid: str, *, after_sequence: int = 0, limit: int = 20
    ) -> dict: ...
    def legacy_get(self, host_id: str, rid: str, legacy_id: str) -> dict: ...
    def legacy_handoff(self, host_id: str, rid: str, legacy_id: str) -> str: ...
    def handoff(self, host_id: str, rid: str, *, run_ref: str | None = None) -> str: ...


def register_defense_recheck_routes(
    app: FastAPI, service: DefenseRecheckRoutes, protected: list
) -> None:
    class RecheckRoute(APIRoute):
        def get_route_handler(self):
            original = super().get_route_handler()

            async def bounded(request):
                try:
                    response = await original(request)
                    response.headers["Cache-Control"] = "no-store"
                    return response
                except RequestValidationError:
                    raise HTTPException(422, "防护复验请求参数不符合固定约定。") from None

            return bounded

    router = APIRouter(
        prefix="/api/hosts/{host_id}/ssh-defense/transactions/{rid}",
        dependencies=protected,
        route_class=RecheckRoute,
    )

    def guarded(call):
        try:
            return call()
        except DefenseConflict:
            raise HTTPException(409, "复验引用、登记或证据绑定无法核实。") from None
        except (sqlite3.Error, OSError, ValueError):
            raise HTTPException(503, "复验记录暂时无法核实，请读取原复验。") from None

    @router.post("/rechecks")
    def start(host_id: HostId, rid: Identifier, body: DefenseRecheckRequest):
        return guarded(lambda: service.start(host_id, rid, body))

    @router.get("/rechecks")
    def history(
        host_id: HostId,
        rid: Identifier,
        after_sequence: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=20)] = 20,
    ):
        return guarded(
            lambda: service.list(host_id, rid, after_sequence=after_sequence, limit=limit)
        )

    @router.get("/rechecks/{run_ref}")
    def get(host_id: HostId, rid: Identifier, run_ref: Identifier):
        return guarded(lambda: service.get(host_id, rid, run_ref))

    @router.post("/rechecks/{run_ref}/interrupt")
    def interrupt(
        host_id: HostId, rid: Identifier, run_ref: Identifier, body: DefenseRecheckInterrupt
    ):
        return guarded(lambda: service.interrupt(host_id, rid, run_ref, body))

    @router.get("/handoff")
    def handoff(host_id: HostId, rid: Identifier, run_ref: Identifier | None = None):
        return guarded(
            lambda: Response(
                service.handoff(host_id, rid, run_ref=run_ref),
                media_type="text/markdown; charset=utf-8",
                headers={"Content-Disposition": 'attachment; filename="opsark-defense-handoff.md"'},
            )
        )

    @router.get("/legacy-rechecks")
    def legacy_history(
        host_id: HostId,
        rid: Identifier,
        after_sequence: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=20)] = 20,
    ):
        return guarded(
            lambda: service.legacy_list(host_id, rid, after_sequence=after_sequence, limit=limit)
        )

    @router.get("/legacy-rechecks/{legacy_id}")
    def legacy_get(host_id: HostId, rid: Identifier, legacy_id: Identifier):
        return guarded(lambda: service.legacy_get(host_id, rid, legacy_id))

    @router.get("/legacy-rechecks/{legacy_id}/handoff")
    def legacy_handoff(host_id: HostId, rid: Identifier, legacy_id: Identifier):
        return guarded(
            lambda: Response(
                service.legacy_handoff(host_id, rid, legacy_id),
                media_type="text/markdown; charset=utf-8",
                headers={
                    "Content-Disposition": 'attachment; filename="opsark-defense-legacy-handoff.md"'
                },
            )
        )

    app.include_router(router)
