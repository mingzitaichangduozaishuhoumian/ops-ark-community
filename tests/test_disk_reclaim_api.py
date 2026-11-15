"""Existing investigation/persistence/export/egress path, entirely local synthetic data."""

import json
from dataclasses import replace
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from test_ai import settings as ai_settings
from test_disk_reclaim import Metadata, check, collection, helper, host, scope, signed

from opsark import ai, collector, main
from opsark.ai_egress import AIEgressBlocked, guard_request, guard_source
from opsark.config import HostConfig
from opsark.disk_reclaim import safe_disk_check
from opsark.models import CheckResult, Report
from opsark.platforms import TOOLS


@pytest.mark.parametrize("bad", [False, True])
def test_investigation_persists_and_exports_same_closed_metadata_and_rejections(
    tmp_path, monkeypatch, bad
):
    settings = ai_settings(tmp_path)
    value = helper.project(scope(), Metadata())
    private = "/srv/unclassified-fixture-path"
    if bad:
        value["objects"][0]["raw_path"] = private
        value = signed(value)
    evidence = collection(check(value))
    monkeypatch.setattr(
        main,
        "list_samples",
        lambda: [
            {"id": "disk-fixture", "scenario": "disk", "title": "Fixture", "host_id": "fixture"}
        ],
    )
    monkeypatch.setattr(main, "collect_replay", lambda _: (host(), evidence))
    calls = []

    def forbidden(*args, **kwargs):
        calls.append(True)
        raise AssertionError("No model transport is authorized in this test")

    monkeypatch.setattr(ai, "request_document", forbidden)
    with TestClient(main.create_app(settings)) as client:
        auth = {"Authorization": "Bearer " + settings.token}
        response = client.post(
            "/api/investigations",
            headers=auth,
            json={"source": "replay", "scenario": "disk", "sample_id": "disk-fixture"},
        )
        assert response.status_code == 200, response.text
        result = response.json()
        assert private not in response.text and "/srv/registered" not in response.text
        readback = client.get("/api/reports/" + result["id"], headers=auth)
        assert readback.json() == result
        export = client.get("/api/reports/" + result["id"] + "/export", headers=auth)
        assert export.status_code == 200
        assert private not in export.text and "/srv/registered" not in export.text
        if bad:
            assert result["ai_egress_block_reason"] == "unclassified_payload"
            explanation = client.post(
                "/api/reports/" + result["id"] + "/explain",
                headers=auth,
                json={"confirm_send": True},
            )
            assert explanation.status_code == 200 and explanation.json()["status"] == "failed"
            assert "拦截" in explanation.json()["text"]
            assert "不提供回收容量估算" in export.text
        else:
            assert result["ai_egress_block_reason"] is None
            assert "0 至 16384 字节" in export.text
            assert "业务数据排除清理" in export.text
            summary = ai.explanation_input(Report.model_validate(result))
            body = {
                "model": settings.ai_model,
                "max_tokens": settings.ai_max_output_tokens,
                "messages": [
                    {"role": "system", "content": ai.egress_system(summary)},
                    {"role": "user", "content": json.dumps(summary)},
                ],
                "response_format": ai.egress_format(settings),
            }
            assert guard_request(body, settings, "diagnosis")
            body["messages"][1]["content"] = json.dumps({**summary, "raw_path": private})
            with pytest.raises(AIEgressBlocked):
                guard_request(body, settings, "diagnosis")
    assert calls == []


def test_sensitive_source_is_blocked_before_projection_and_cannot_survive_report(tmp_path):
    settings = ai_settings(tmp_path)
    # Construct only a synthetic value; no credential, key block, SQL or real content is read.
    value = helper.project(scope(), Metadata())
    value["objects"][0]["unknown"] = "token" + "=synthetic-disk-source-canary"
    source = check(signed(value))
    with pytest.raises(AIEgressBlocked, match="敏感"):
        guard_source(source.model_dump(mode="json"), settings)
    safe, rejected = safe_disk_check(source, helper.digest(scope()))
    assert rejected and "canary" not in safe.model_dump_json()


def test_target_timeout_error_retains_timeout_without_partial_objects():
    reply = check(
        {
            "schema": "opsark-disk-reclaim-error/v1",
            "reason": "collection_timeout",
            "actions_enabled": False,
        }
    ).model_copy(update={"status": "error", "exit_code": 1})
    safe, rejected = safe_disk_check(reply, helper.digest(scope()))
    assert rejected and safe.status == "timeout" and not safe.stdout
    assert "超时" in safe.stderr


def test_local_mapping_cannot_enter_investigation_export_or_model(tmp_path, monkeypatch):
    baseline = helper.project(scope(), Metadata())
    located = helper.locate(
        scope(),
        baseline["objects"][0]["object_ref"],
        helper.digest(scope()),
        baseline["snapshot_digest"],
        Metadata(),
    )
    monkeypatch.setattr(
        main,
        "list_samples",
        lambda: [
            {"id": "disk-fixture", "scenario": "disk", "title": "Fixture", "host_id": "fixture"}
        ],
    )
    monkeypatch.setattr(main, "collect_replay", lambda _: (host(), collection(check(located))))
    settings = ai_settings(tmp_path)
    calls = []
    monkeypatch.setattr(ai, "request_document", lambda *a, **kw: calls.append(True))
    with TestClient(main.create_app(settings)) as client:
        auth = {"Authorization": "Bearer " + settings.token}
        response = client.post(
            "/api/investigations",
            headers=auth,
            json={"source": "replay", "scenario": "disk", "sample_id": "disk-fixture"},
        )
        assert response.status_code == 200
        result = response.json()
        assert result["ai_egress_block_reason"] == "unclassified_payload"
        assert "/srv/" not in response.text and "locations" not in response.text
        export = client.get("/api/reports/" + result["id"] + "/export", headers=auth)
        assert "/srv/" not in export.text and "locations" not in export.text
        explanation = client.post(
            "/api/reports/" + result["id"] + "/explain", headers=auth, json={"confirm_send": True}
        )
        assert explanation.json()["status"] == "failed"
    assert calls == []


def test_registered_ssh_investigation_uses_exact_helper_and_preserves_report_evidence(
    tmp_path, monkeypatch
):
    settings = ai_settings(tmp_path)
    public = host().model_copy(update={"source": "ssh", "trusted_hosts_digest": "a" * 64})
    target = HostConfig(
        public=public,
        key_file=Path("unused-private-reference"),
        known_hosts_file=Path("unused-trust-reference"),
    )
    probes = {item.name: item for item in collection(check()).checks}
    probes["platform_tools"] = CheckResult(
        name="platform_tools",
        stdout=("OPSARK_ARCH=x86_64\n" + "".join("OPSARK_TOOL_" + name + "=1\n" for name in TOOLS)),
    )
    sent, connected = [], []

    class Client:
        def close(self):
            pass

    def run(_client, name, command, _budget):
        sent.append(command)
        return probes[name]

    monkeypatch.setattr(collector.paramiko, "SSHClient", Client)
    monkeypatch.setattr(
        collector,
        "_connect_registered",
        lambda _client, registered: connected.append(registered.public.id),
    )
    monkeypatch.setattr(collector, "run_check", run)
    monkeypatch.setattr(main, "load_hosts", lambda _: {"fixture": target})
    with TestClient(
        main.create_app(replace(settings, ai_key=None, ai_base_url=None, ai_model=None))
    ) as client:
        auth = {"Authorization": "Bearer " + settings.token}
        response = client.post(
            "/api/investigations",
            headers=auth,
            json={"source": "ssh", "scenario": "disk", "host_id": "fixture"},
        )
        assert response.status_code == 200, response.text
        result = response.json()
        assert result["compatibility"]["status"] == "compatible"
        assert result["ai_egress_block_reason"] is None
        assert any("0 至 16384 字节" in item["text"] for item in result["facts"])
        assert result["source"] == "ssh"
        assert all("registered-logs" not in item["output"] for item in result["evidence"])
    assert connected == ["fixture"]
    assert "timeout -k 1s 5s /usr/local/libexec/opsark-disk-reclaim" in sent
    assert not any("du -xsk" in command for command in sent)
