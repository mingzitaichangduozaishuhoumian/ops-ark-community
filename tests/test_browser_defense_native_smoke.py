"""Only fake provider bytes, synthetic Root and loopback browser traffic."""

import asyncio
import hashlib
import json
from collections import Counter
from dataclasses import replace
from datetime import UTC, datetime
from types import SimpleNamespace

import browser_defense_native_smoke as acceptance
import httpx
import pytest
import test_defense_api as root_fixture
from playwright.sync_api import Error, expect, sync_playwright
from test_defense_application import main_module as main_module
from test_defense_client import keyset as keyset
from test_defense_client import target as target

from opsark import ai_provider
from opsark.config import Settings
from opsark.defense_client import DefenseTarget, RoleCredential
from opsark.defense_models import canonical, digest
from opsark.defense_policy import DefenseAIConsent

TOKEN = "synthetic-native-browser-console-token-only"
PROVIDER_TOKEN = "synthetic-native-browser-provider-token-only"
SUMMARY = {
    "v": 1,
    "candidates": [
        {
            "candidate_alias": "candidate-1",
            "evidence_alias": "evidence-1",
            "classification": "eligible",
            "distinct_failure_ports": 5,
            "ttl_seconds": 60,
        }
    ],
    "omitted_candidate_count": 1,
}
PROPOSAL = {
    "v": 1,
    "decision": "propose_defense",
    "candidate_alias": "candidate-1",
    "evidence_aliases": ["evidence-1"],
    "reason_code": "evidence_sufficient",
}


def settings(tmp_path, **fields):
    return Settings(
        data_dir=tmp_path / "fresh",
        token=TOKEN,
        ai_base_url="https://newfake-provider.example/v1",
        ai_key=PROVIDER_TOKEN,
        ai_model="synthetic-native-browser-model",
        **fields,
    )


def outgoing(config):
    result = acceptance.request_body(SUMMARY, config)
    result[config.ai_token_limit_parameter] = config.ai_max_output_tokens
    if config.ai_thinking_mode != "provider_default":
        result["thinking"] = {"type": config.ai_thinking_mode}
    return result


def check_original_receipt_dom_order(legacy_first):
    receipts = (
        '<details class="ssh-defense-history-detail"><summary>历史回执 · 2 条</summary>'
        '<ol class="ssh-defense-receipts"><li>apply · unavailable</li>'
        "<li>query · active</li></ol></details>"
    )
    legacy = (
        '<section class="ssh-defense-rechecks"><details class="ssh-defense-legacy">'
        "<summary>早期工程复验记录 · 仅供历史查阅</summary><p>旧记录仍待验收</p>"
        "</details></section>"
    )
    with sync_playwright() as playwright:
        browser = playwright.chromium.launch()
        try:
            page = browser.new_page()
            page.set_content(
                '<article data-defense="detail">'
                + (legacy + receipts if legacy_first else receipts + legacy)
                + "</article>"
            )
            expect(page.locator('[data-defense="detail"] summary')).to_have_count(2)
            original = acceptance._open_transaction_receipt_history(page)
            expect(original).to_contain_text("unavailable")
            expect(original).to_contain_text("query · active")
            assert (
                page.locator("details.ssh-defense-legacy").evaluate("element => element.open")
                is False
            )
            acceptance._open_transaction_receipt_history(page)
            expect(original).to_be_visible()
        finally:
            browser.close()


def test_loader_keeps_six_bindings_and_only_references_original_key(tmp_path, monkeypatch):
    value = {
        "base_url": "https://newfake-provider.example/v1",
        "model": "synthetic-native-browser-model",
        "response_format": "json_prompt",
        "token_limit_parameter": "max_completion_tokens",
        "max_output_tokens": 512,
        "thinking_mode": "disabled",
    }
    config_path, key_path = tmp_path / "fixture-config.json", tmp_path / "fixture-key"
    monkeypatch.setenv("OPSARK_NATIVE_SMOKE_PROVIDER_CONFIG", str(config_path))
    monkeypatch.setenv("OPSARK_NATIVE_SMOKE_PROVIDER_KEY", str(key_path))
    calls, seal = [], object()

    def reader(path, limit, *, private):
        calls.append((path, limit, private))
        assert path == config_path
        return canonical(value), seal

    monkeypatch.setattr(acceptance, "_read_file", reader)
    loaded = acceptance.load_existing_provider_settings(
        tmp_path / "fresh", TOKEN, tmp_path / "hosts", tmp_path / "identities", tmp_path / "policy"
    )
    assert ai_provider.provider_binding_fields(loaded) == value
    assert loaded.ai_key is None and loaded.ai_key_file == key_path
    assert len(calls) == 2 and all(row == (config_path, 16384, False) for row in calls)
    assert not loaded.observation_enabled and not loaded.defense_worker_enabled


@pytest.mark.parametrize(
    "raw",
    [
        b'{"base_url":"https://fake.example/v1","model":"fake","key":"private-fake-canary"}',
        b'{"base_url":"https://fake.example/v1","model":"fake","model":"fake"}',
        b'{"base_url":"https://fake.example/v1","model":"fake","max_output_tokens":NaN}',
        b'{"base_url":"http://remote-fake.example/v1","model":"fake"}',
        b'{"base_url":"https://fake.example/v1","model":1}',
    ],
)
def test_loader_rejects_unknown_duplicate_nonfinite_or_invalid_without_reflection(
    tmp_path, monkeypatch, raw
):
    config_path, key_path = tmp_path / "fixture-config.json", tmp_path / "fixture-key"
    monkeypatch.setenv("OPSARK_NATIVE_SMOKE_PROVIDER_CONFIG", str(config_path))
    monkeypatch.setenv("OPSARK_NATIVE_SMOKE_PROVIDER_KEY", str(key_path))
    calls = []

    def reader(path, limit, *, private):
        calls.append((path, limit, private))
        return raw, object()

    monkeypatch.setattr(acceptance, "_read_file", reader)
    with pytest.raises(acceptance.NativeBrowserError) as raised:
        acceptance.load_existing_provider_settings(tmp_path, TOKEN, tmp_path, tmp_path, tmp_path)
    assert raised.value.code == "provider_configuration_invalid"
    assert "private-fake-canary" not in str(raised.value)
    assert calls == [(config_path, 16384, False)]


def test_observer_delegates_once_and_restores_original_send(tmp_path, monkeypatch):
    calls = []

    async def delegate(_client, request, **_kwargs):
        calls.append(request)
        return httpx.Response(200)

    monkeypatch.setattr(httpx.AsyncClient, "send", delegate)
    config = settings(tmp_path, ai_thinking_mode="disabled")
    observer = acceptance.ProviderObserver(config)
    observer.arm(SUMMARY)

    async def exercise():
        with observer.installed():
            async with httpx.AsyncClient(trust_env=False) as client:
                request = httpx.Request("POST", "https://fake.example/v1", json=outgoing(config))
                assert (await client.send(request)).status_code == 200
                with pytest.raises(acceptance.NativeBrowserError) as rejected:
                    await client.send(request)
                assert rejected.value.code == "provider_extra_attempt_blocked"

    asyncio.run(exercise())
    assert httpx.AsyncClient.send is delegate
    assert len(calls) == observer.dispatches == observer.responses == 1 and observer.entries == 2
    proof = json.dumps(observer.safe())
    assert not any(
        secret in proof for secret in (PROVIDER_TOKEN, TOKEN, "fake.example", config.ai_model)
    )


@pytest.mark.parametrize("case", ["unarmed", "changed_body", "forbidden_reference"])
def test_observer_blocks_before_delegating(tmp_path, monkeypatch, case):
    calls = []

    async def delegate(*_a, **_kw):
        calls.append(True)
        return httpx.Response(200)

    monkeypatch.setattr(httpx.AsyncClient, "send", delegate)
    config = settings(tmp_path)
    observer = acceptance.ProviderObserver(config)
    if case != "unarmed":
        observer.arm(SUMMARY, references=("candidate-1",) if case == "forbidden_reference" else ())
    document = outgoing(config)
    if case == "changed_body":
        document["extra"] = "private-fake-canary"

    async def exercise():
        with observer.installed():
            async with httpx.AsyncClient(trust_env=False) as client:
                with pytest.raises(acceptance.NativeBrowserError):
                    await client.send(httpx.Request("POST", "https://fake.example", json=document))

    asyncio.run(exercise())
    assert not calls and observer.entries == 1 and observer.dispatches == 0


def test_proof_is_bounded_noclobber_and_rejects_unclassified_native_snapshot(tmp_path):
    proof = tmp_path / "proof.json"
    acceptance._write_proof(proof, {"completed": False, "phase": "unknown"})
    with pytest.raises(acceptance.NativeBrowserError):
        acceptance._write_proof(proof, {"completed": True})
    assert json.loads(proof.read_text())["completed"] is False
    with pytest.raises(acceptance.NativeBrowserError):
        acceptance._snapshot(
            lambda: {"usage_count": 0, "intents": 0, "kernel_active": False, "raw_log": "fake"}
        )


@pytest.mark.parametrize("case", ["old_database", "patch_reference", "webhook_reference"])
def test_entry_rejects_existing_history_and_unrelated_deployment_references(tmp_path, case):
    config = settings(tmp_path)
    if case == "old_database":
        config.data_dir.mkdir()
        (config.data_dir / "security.sqlite3").write_bytes(b"synthetic-unread-database-sentinel")
    elif case == "patch_reference":
        config = replace(config, patch_inventory_path=tmp_path / "unread-synthetic-patch-reference")
    else:
        config = replace(
            config, vulnerability_scan_enabled=True, vulnerability_scan_host_ids=("fixture",)
        )

    def forbidden(*_args):
        pytest.fail("invalid settings reached a native callback")

    with pytest.raises(acceptance.NativeBrowserError) as raised:
        acceptance.run_native_browser(
            config,
            stimulate_after_arm=forbidden,
            snapshot=forbidden,
            health=forbidden,
            proof_path=tmp_path / "never-created.json",
        )
    assert raised.value.code == "settings_scope_invalid"
    assert not (tmp_path / "never-created.json").exists()


@pytest.fixture
def assembled(tmp_path, monkeypatch, target, keyset, main_module):
    with sync_playwright() as playwright:
        try:
            browser = playwright.chromium.launch()
        except Error as error:
            pytest.skip("Playwright Chromium unavailable: " + type(error).__name__)
        browser.close()
    pin = tmp_path / "loopback-pin"
    pin.write_text(f"[127.0.0.1]:22423 {keyset[0].get_name()} {keyset[0].get_base64()}\n")
    credentials = [
        RoleCredential(
            getattr(target, role).username,
            22423,
            getattr(target, role).key_file,
            pin,
            hashlib.sha256(pin.read_bytes()).hexdigest(),
        )
        for role in ("readonly", "observe", "control")
    ]
    loopback = DefenseTarget(
        replace(
            target.host,
            public=target.host.public.model_copy(update={"address": "127.0.0.1"}),
            known_hosts_file=pin,
        ),
        *credentials,
        target.root_scope_sha256,
        target.root_policy_sha256,
        target.boot_ref,
        target.binding_ref,
        target.other_key_files,
    )
    now = datetime.now(UTC)
    monkeypatch.setattr(root_fixture, "NOW", now)
    config = settings(tmp_path)
    deployment = root_fixture.policy(loopback)
    deployment = deployment.model_copy(
        update={
            "execution": deployment.execution.model_copy(
                update={"max_actions_per_day": 1, "max_total_actions": 1}
            ),
            "ai": DefenseAIConsent(
                enabled=True,
                provider_fingerprint=ai_provider.provider_fingerprint(config),
                max_analyses_per_day=1,
                max_total_analyses=1,
                requires_ai=True,
            ),
        }
    )
    monkeypatch.setattr(main_module, "load_hosts", lambda _: {"fixture": loopback.host})
    monkeypatch.setattr(main_module, "load_patch_targets", lambda *_: {})
    monkeypatch.setattr(main_module, "load_defense_targets", lambda *_: {"fixture": loopback})
    monkeypatch.setattr(main_module, "load_defense_policy", lambda _: deployment)
    root = root_fixture.FakeRoot(loopback, lambda: now)
    root.lose = "apply"
    applications = []
    original_create = main_module.create_app

    def create(value):
        app = original_create(value)
        app.state.defense_service.invoker = root
        app.state.defense_service.clock = lambda: now
        app.state.defense_ai_service.now = lambda: now
        applications.append(app)
        return app

    monkeypatch.setattr(main_module, "create_app", create)
    return SimpleNamespace(settings=config, root=root, applications=applications)


@pytest.mark.parametrize("outcome", ["proposal", "no_action", "timeout"])
def test_real_application_restart_workflow_with_shared_fake_root_and_mock_provider(
    assembled,
    tmp_path,
    monkeypatch,
    outcome,
):
    h = assembled
    calls = []
    original_client = httpx.AsyncClient

    def respond(request):
        calls.append(request)
        if outcome == "timeout":
            raise httpx.ReadTimeout("synthetic-private-provider-error", request=request)
        output = (
            PROPOSAL
            if outcome == "proposal"
            else PROPOSAL
            | {
                "decision": "no_action",
                "candidate_alias": None,
                "evidence_aliases": [],
                "reason_code": "no_match",
            }
        )
        return httpx.Response(
            200,
            json={
                "choices": [
                    {
                        "finish_reason": "stop",
                        "message": {"role": "assistant", "content": json.dumps(output)},
                    }
                ]
            },
        )

    class LocalClient(original_client):
        def __init__(self, **kwargs):
            super().__init__(transport=httpx.MockTransport(respond), **kwargs)

    monkeypatch.setattr(ai_provider.httpx, "AsyncClient", LocalClient)

    def snapshot():
        records = list(h.root.records.values())
        applied = sum("active_until" in record for record in records)
        return {
            "usage_count": applied,
            "intents": applied,
            "kernel_active": any(record.get("state") == "active" for record in records),
            "records": dict(Counter(record["kind"] for record in records)),
            "ledger_sha256": digest(
                [(key, value.get("state")) for key, value in h.root.records.items()]
            ),
        }

    stimulated = []

    def stimulate(cursor):
        assert cursor in h.root.records
        stimulated.append(cursor)
        return {"stimulated": True}

    proof_path = tmp_path / "acceptance.json"
    result = acceptance.run_native_browser(
        h.settings,
        stimulate_after_arm=stimulate,
        snapshot=snapshot,
        health=lambda: {
            "management_ssh_ok": True,
            "contrast_ssh_ok": True,
            "same_source_http_ok": True,
        },
        proof_path=proof_path,
    )
    assert json.loads(proof_path.read_text()) == result
    assert len(calls) == result["provider"]["transport_dispatches"] == 1
    assert len(stimulated) == 1
    assert all(app.state.defense_service.stopped.is_set() for app in h.applications)
    assert sum(op == "arm" for op, _ in h.root.sent) == 1
    if outcome == "proposal":
        assert result["completed"], json.dumps(result, sort_keys=True)
        assert len(h.applications) == result["same_python_new_application_instances"] == 2
        assert (
            result["first_application_lifespan_stopped"]
            and result["final_application_lifespan_stopped"]
        )
        assert result["reconciled_original_task_after_application_restart"]
        assert result["old_history_reopened_after_application_restart"]
        assert result["unknown_latch_retained"] and result["ai_usage_state"] == "consumed"
        for operation in ("prepare", "apply", "revoke"):
            assert sum(op == operation for op, _ in h.root.sent) == 1
        for legacy_first in (True, False):
            check_original_receipt_dom_order(legacy_first)
    else:
        assert not result["completed"] and result["phase"] == "ai_did_not_authorize_proposal"
        assert result["ai_status"] == ("unknown" if outcome == "timeout" else "completed")
        assert not any(op in {"prepare", "apply", "revoke"} for op, _ in h.root.sent)
        assert result["local_transaction_counts"]["action"] == 0
    raw = proof_path.read_text()
    assert not any(
        secret in raw
        for secret in (TOKEN, PROVIDER_TOKEN, h.settings.ai_model, "fake-provider.example")
    )
