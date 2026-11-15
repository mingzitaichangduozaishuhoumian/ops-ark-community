"""Explicit advice consent over registered defense sources, with no execution endpoints."""

import sqlite3
from typing import Annotated, Literal

from fastapi import APIRouter, FastAPI, HTTPException, Query
from fastapi.exceptions import RequestValidationError
from fastapi.routing import APIRoute
from pydantic import Field, model_validator

from opsark.ai_egress import AIEgressBlocked
from opsark.defense_ai import DefenseAIBlocked, DefenseAIService
from opsark.defense_client import DefenseClientError
from opsark.defense_models import DefenseModel, Digest, Identifier
from opsark.defense_policy import HostId
from opsark.defense_store import DefenseConflict


class DefenseAnalysisRequest(DefenseModel):
    cursor_request_id: Identifier
    source_ref: Identifier
    expected_input_digest: Digest
    expected_mode_revision: int = Field(ge=0, le=2**31 - 2)
    confirm_send: Literal[True]

    @model_validator(mode="before")
    @classmethod
    def exact_confirmation(cls, value):
        if type(value) is not dict or value.get("confirm_send") is not True:
            raise ValueError("必须明确同意发送这一份白名单摘要。")
        return value


class DefensePreviewRequest(DefenseModel):
    cursor_request_id: Identifier
    source_ref: Identifier


def register_defense_ai_routes(
    application: FastAPI, service: DefenseAIService, protected: list
) -> None:
    class DefenseAIRoute(APIRoute):
        def get_route_handler(self):
            original = super().get_route_handler()

            async def bounded(request):
                try:
                    return await original(request)
                except RequestValidationError:
                    raise HTTPException(422, "防护分析请求参数不符合固定约定。") from None

            return bounded

    router = APIRouter(prefix="/api", dependencies=protected, route_class=DefenseAIRoute)

    def guarded(call):
        try:
            return call()
        except AIEgressBlocked:
            raise HTTPException(
                409, "防泄密门禁已拦截本次防护分析，原任务与费用意图保留。"
            ) from None
        except (DefenseAIBlocked, DefenseConflict, ValueError):
            raise HTTPException(
                409, "防护分析的范围、许可或摘要已变化，请重新核对原记录。"
            ) from None
        except (DefenseClientError, sqlite3.Error, OSError):
            raise HTTPException(
                503, "防护分析状态暂时无法核实，请读取原分析，不要重复发送。"
            ) from None

    @router.get("/hosts/{host_id}/ssh-defense/ai/preview")
    def preview(host_id: HostId, query: Annotated[DefensePreviewRequest, Query()]):
        return guarded(lambda: service.preview(host_id, query.cursor_request_id, query.source_ref))

    @router.post("/hosts/{host_id}/ssh-defense/ai/analyses")
    def analyze(host_id: HostId, body: DefenseAnalysisRequest):
        return guarded(
            lambda: service.analyze(
                host_id,
                body.cursor_request_id,
                body.source_ref,
                expected_input_digest=body.expected_input_digest,
                expected_mode_revision=body.expected_mode_revision,
                confirm_ai=True,
                automatic=False,
            )
        )

    @router.get("/hosts/{host_id}/ssh-defense/ai/analyses/{analysis_id}")
    def get(host_id: HostId, analysis_id: Identifier):
        return guarded(lambda: service.get(host_id, analysis_id))

    application.include_router(router)
