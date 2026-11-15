"""Authenticated local views of read-only original-task follow-up."""

from __future__ import annotations

import sqlite3
from collections.abc import Callable
from datetime import datetime
from typing import Annotated, Literal, Protocol

from fastapi import APIRouter, FastAPI, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import model_validator

from opsark.defense_models import DefenseModel, Identifier
from opsark.defense_store import DefenseConflict


class TaskWatchAcknowledge(DefenseModel):
    confirm_ack: Literal[True]

    @model_validator(mode="before")
    @classmethod
    def exact_confirmation(cls, value):
        if type(value) is not dict or value.get("confirm_ack") is not True:
            raise ValueError("An explicit acknowledgement is required")
        return value


class TaskWatchStatus(Protocol):
    @property
    def clock(self) -> Callable[[], datetime]: ...

    def status(self) -> dict: ...


class TaskWatchEvents(Protocol):
    def events(self, *, after_sequence: int = 0, limit: int = 20) -> dict: ...
    def ack(
        self, event_ref: str, *, confirm_ack: bool = True, now: datetime | None = None
    ) -> dict: ...


def register_defense_task_watch_routes(
    app: FastAPI, watcher: TaskWatchStatus, store: TaskWatchEvents, protected: list
) -> None:
    class TaskWatchRoute(APIRoute):
        def get_route_handler(self):
            original = super().get_route_handler()

            async def bounded(request):
                try:
                    response = await original(request)
                    response.headers["Cache-Control"] = "no-store"
                    return response
                except RequestValidationError:
                    raise HTTPException(422, "原任务跟进请求不符合固定约定。") from None

            return bounded

    router = APIRouter(
        prefix="/api/ssh-defense/task-watch", dependencies=protected, route_class=TaskWatchRoute
    )

    def guarded(call):
        try:
            return call()
        except DefenseConflict:
            raise HTTPException(409, "原任务跟进记录无法核实。") from None
        except (sqlite3.Error, OSError, ValueError):
            raise HTTPException(503, "原任务跟进记录暂时不可用。") from None

    @router.get("")
    def status():
        return guarded(lambda: {"v": 1, **watcher.status()})

    @router.get("/events")
    def events(
        after_sequence: Annotated[int, Query(ge=0)] = 0,
        limit: Annotated[int, Query(ge=1, le=20)] = 20,
    ):
        return guarded(lambda: {"v": 1, **store.events(after_sequence=after_sequence, limit=limit)})

    @router.post("/events/{event_ref}/ack")
    def acknowledge(event_ref: Identifier, body: TaskWatchAcknowledge):
        return guarded(
            lambda: store.ack(event_ref, confirm_ack=body.confirm_ack, now=watcher.clock())
        )

    app.include_router(router)
