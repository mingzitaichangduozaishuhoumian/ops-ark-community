"""Exercise the operator browser driver with owned test transports, never remote hosts."""

from collections import Counter
from dataclasses import replace
from datetime import UTC, datetime

import browser_defense_business_smoke as smoke
import test_defense_api as root_fixture
from test_defense_application import main_module as main_module
from test_defense_client import keyset as keyset
from test_defense_client import target as target

from opsark.business_readiness import BusinessCheckResult, BusinessReadiness
from opsark.config import Settings
from opsark.defense_models import digest
from opsark.models import BusinessCheck


def test_operator_browser_driver_uses_one_original_action_and_three_readonly_runs(
    tmp_path, target, keyset, monkeypatch, main_module
):
    now = datetime.now(UTC)
    monkeypatch.setattr(root_fixture, "NOW", now)
    pin = tmp_path / "collector-known-hosts"
    pin.write_text(f"192.0.2.10 {keyset[0].get_name()} {keyset[0].get_base64()}\n")
    pin.chmod(0o600)
    import hashlib

    public = target.host.public.model_copy(
        update={"trusted_hosts_digest": hashlib.sha256(pin.read_bytes()).hexdigest()}
    )
    checks = tuple(
        BusinessCheck(
            id=name,
            domain="business.opsark.invalid",
            port=42180,
            path="/" + name,
            expected_body_sha256="a" * 64,
            read_only_confirmed=True,
        )
        for name in ("health", "application", "dependency")
    )
    target = replace(
        target,
        host=replace(target.host, public=public, known_hosts_file=pin, business_checks=checks),
    )
    monkeypatch.setattr(main_module, "load_hosts", lambda _: {"fixture": target.host})
    monkeypatch.setattr(main_module, "load_patch_targets", lambda *_: {})
    monkeypatch.setattr(main_module, "load_defense_targets", lambda *_: {"fixture": target})
    monkeypatch.setattr(main_module, "load_defense_policy", lambda _: root_fixture.policy(target))
    phase = ["restored"]
    collections = []
    root = root_fixture.FakeRoot(target, lambda: now)
    root.lose = "apply"

    def collect(host):
        assert host == target.host
        collections.append(phase[0])
        rows = []
        for check in checks:
            code = 503 if phase[0] == "mixed" and check.id == "application" else 200
            incomplete = phase[0] != "restored" and check.id == "dependency"
            rows.append(
                BusinessCheckResult(
                    id=check.id,
                    status="inconclusive" if incomplete else "failed" if code == 503 else "passed",
                    http_status=None if incomplete else code,
                    status_matches=None if incomplete else code == 200,
                    body_matches=None if incomplete or code == 503 else True,
                )
            )
        return BusinessReadiness(
            host_id="fixture",
            status="failed"
            if phase[0] == "mixed"
            else "inconclusive"
            if phase[0] == "timeout_only"
            else "passed",
            checks=rows,
        )

    original = main_module.create_app

    def create(settings):
        app = original(settings)
        app.state.defense_service.invoker = root
        app.state.defense_service.clock = lambda: now
        app.state.defense_recheck_service.clock = lambda: now
        app.state.defense_recheck_service.collector = collect
        return app

    monkeypatch.setattr(main_module, "create_app", create)

    def change(value):
        phase[0] = value
        return {"phase": value}

    def snapshot():
        records = list(root.records.values())
        return {
            "ledger": {
                "usage_count": sum("active_until" in r for r in records),
                "intents": sum("active_until" in r for r in records),
                "kernel_active": any(r.get("state") == "active" for r in records),
                "records": dict(Counter(r["kind"] for r in records)),
                "ledger_sha256": digest([(k, v.get("state")) for k, v in root.records.items()]),
            }
        }

    settings = Settings(tmp_path / "new-data", "synthetic-business-driver-console-token-only")
    result = smoke.run_business_browser(
        settings,
        stimulate_after_arm=lambda cursor: {"cursor_request_id": cursor},
        change_phase=change,
        snapshot=snapshot,
        proof_path=tmp_path / "proof.json",
    )
    assert result["completed"], result
    assert result["ai_dispatches"] == 0
    assert result["production_root_invoker"] is False
    assert result["production_business_collector"] is False
    assert collections == ["mixed", "timeout_only", "restored"]
    assert sum(op == "apply" for op, _ in root.sent) == 1
    assert sum(op == "revoke" for op, _ in root.sent) == 1
    assert result["old_reports_reopened_after_application_rebuild"]
