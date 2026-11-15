"""Native age v2 round trips; only freshly generated keys and synthetic ten-store data."""

from types import SimpleNamespace

import pytest
from test_defense_backup_compat import contents
from test_defense_backup_compat import history as history_fixture
from test_sealed_backup import (
    digest,
    new_identity,
    private_directory,
    private_file,
    public_result,
    restore_case,
    restrict_owned_windows_fixture,
    seal_case,
)
from test_sealed_backup import (
    native_tools as native_tools,
)
from test_sealed_defense import bundle, raw_json

from opsark.defense_store import DefenseStore
from tools import sealed_backup as sealed


@pytest.fixture
def native_v2_case(tmp_path, native_tools):
    restrict_owned_windows_fixture(tmp_path)
    history = history_fixture.__wrapped__(tmp_path)  # ty: ignore[unresolved-attribute] -- owned synthetic fixture, ACL restricted before construction.
    config = private_directory(tmp_path / "configuration")
    plan, documents = bundle()
    # Preserve an inline canary as raw configuration inside the authenticated
    # ciphertext. Dedicated credentials remain references and are never followed.
    documents["observer.env"] += b"OPSARK_AI_KEY=synthetic-v2-inline-canary\n"
    documents["handover.json"] = raw_json(plan)
    for name, body in documents.items():
        path = config / name
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        private_file(path, body)
    identity, recipient = new_identity(tmp_path, native_tools, "synthetic-identity")
    wrong, _ = new_identity(tmp_path, native_tools, "synthetic-wrong-identity")
    return SimpleNamespace(
        root=tmp_path,
        history=history,
        snapshot=history.snapshot,
        config=config,
        documents=documents,
        identity=identity,
        wrong_identity=wrong,
        recipient_file=private_file(tmp_path / "recipient", recipient),
        ciphertext=tmp_path / "sealed-v2.age",
        tools=native_tools,
    )


def test_native_v2_authentication_preserves_defense_configuration_and_ten_stores(native_v2_case):
    c = native_v2_case
    before = {path.name: path.read_bytes() for path in c.snapshot.iterdir()}
    sealed_result = seal_case(c, profile="observer-handover-v2", config_root=c.config)
    public_result(sealed_result, c.root)
    assert sealed_result["schema_version"] == 2 and sealed_result["sealed"]
    assert sealed_result["inline_config_secrets_may_be_present"]
    assert b"synthetic-v2-inline-canary" not in c.ciphertext.read_bytes()
    assert b"AGE-SECRET-KEY-" not in c.ciphertext.read_bytes()
    assert sealed.check_ciphertext(c.ciphertext, digest(c.ciphertext))["ciphertext_matched"]
    restored_result = restore_case(c)
    public_result(restored_result, c.root)
    assert restored_result["restored"] and restored_result["full_authentication_before_extraction"]
    assert not restored_result["configuration_activated"]
    assert not restored_result["credential_files_restored"]
    assert not restored_result["leases_cleared"] and not restored_result["image_loaded"]
    recovered = c.root / "restored"
    for name, body in c.documents.items():
        assert (recovered / "config-original" / name).read_bytes() == body
    for name, body in before.items():
        assert (recovered / "stores" / name).read_bytes() == body
        assert (c.snapshot / name).read_bytes() == body
    store = DefenseStore(recovered / "stores/security.sqlite3")
    assert contents(store.path) == contents(c.snapshot / "security.sqlite3")
    assert store.transaction(c.history.action.rid).query_required
    assert store.usage(c.history.permit.intent_key).state == "unknown"
    assert store.latched(c.history.action.context.host_id, c.history.action.context.defense_scope)
    assert not list(recovered.rglob("*.key")) and not list(recovered.rglob("access-token"))


@pytest.mark.parametrize("damage", ["wrong_identity", "authenticated_ciphertext_tamper"])
def test_native_v2_authentication_failure_never_extracts(native_v2_case, monkeypatch, damage):
    c = native_v2_case
    seal_case(c, profile="observer-handover-v2", config_root=c.config)
    if damage == "authenticated_ciphertext_tamper":
        body = bytearray(c.ciphertext.read_bytes())
        body[-1] ^= 1
        c.ciphertext.write_bytes(body)
    extractions = []

    def no_unauthenticated_extraction(*_args, **_kwargs):
        extractions.append(True)
        raise AssertionError("Unauthenticated extraction is forbidden")

    monkeypatch.setattr(sealed, "_extract_archive", no_unauthenticated_extraction)
    output = c.root / "must-not-exist"
    with pytest.raises(sealed.BackupError):
        restore_case(
            c,
            output=output,
            identity=c.wrong_identity if damage == "wrong_identity" else c.identity,
        )
    assert not extractions and not output.exists()
