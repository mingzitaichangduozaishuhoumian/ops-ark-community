"""Check the private target receipt and the closed public comparison."""

import json
from dataclasses import replace
from datetime import UTC, datetime, timedelta

import pytest

from opsark import compose_generation as generation
from opsark.config import HostConfig, compose_generation_scope_sha256
from opsark.models import CheckResult, HostPublic

AT = datetime(2026, 4, 12, tzinfo=UTC)
PROJECT, SERVICE, CONTAINER = "fixture-project", "fixture-service", "fixture-container"
SCOPE = compose_generation_scope_sha256(PROJECT, CONTAINER, SERVICE)
RECEIPT = {
    "schema": "opsark-compose-generation/v1",
    "status": "observed",
    "reason": None,
    "scope_digest": SCOPE,
    "binding": "01" * 32,
    "container": "12" * 32,
    "image": "23" * 32,
    "configuration": "34" * 32,
    "compose_version": "45" * 32,
}


def make_host(tmp_path):
    return HostConfig(
        HostPublic(
            id="test",
            name="Fixture",
            address="192.0.2.5",
            source="ssh",
            trusted_hosts_digest="a" * 64,
            container_name=CONTAINER,
        ),
        tmp_path / "key",
        tmp_path / "known-hosts",
        compose_project=PROJECT,
        compose_generation_service=SERVICE,
        compose_generation_scope_digest=SCOPE,
    )


@pytest.fixture
def host(tmp_path):
    return make_host(tmp_path)


def check(value=RECEIPT, **updates):
    return CheckResult(name=generation.CHECK, stdout=json.dumps(value) + "\n", **updates)


def observation(host, seconds=0, **updates):
    return generation.private_observation(
        check(RECEIPT | updates), host, observed_at=AT + timedelta(seconds=seconds)
    )


def test_fixed_command_and_bounded_transport(host, monkeypatch):
    assert generation.collection_command(host) == (
        "timeout -k 1s 5s /usr/local/libexec/opsark-compose-generation"
    )

    def collect(target, commands, *, output_limit):
        assert target is host
        assert commands == {generation.CHECK: generation.COMMAND}
        assert output_limit == generation.MAX_OUTPUT + 1
        return {generation.CHECK: check()}

    monkeypatch.setattr(generation, "collect_registered_receipts", collect)
    result = generation.collect_generation(host)
    assert result is not None and result.key_epoch == RECEIPT["binding"]


@pytest.mark.parametrize(
    "fields",
    [
        {"compose_generation_scope_digest": None},
        {"compose_generation_service": "another-service"},
        {"compose_generation_service": "invalid --all"},
        {"compose_project": None},
        {"container_binding_confirmed": False},
    ],
)
def test_unenrolled_scope_refused_before_collection(host, fields):
    with pytest.raises(generation.GenerationUnavailable):
        generation.collection_command(replace(host, **fields))


@pytest.mark.parametrize(
    "fields", [{"source": "replay"}, {"trusted_hosts_digest": None}, {"username": "observer"}]
)
def test_replay_or_unpinned_target_refused(host, fields):
    with pytest.raises(generation.GenerationUnavailable):
        generation.collection_command(replace(host, public=host.public.model_copy(update=fields)))


@pytest.mark.parametrize(
    "updates",
    [
        {"scope_digest": "1" * 64},
        {"status": "unavailable", "reason": "collection_timeout"},
        {"schema": "opsark-compose-generation/v2"},
        {"configuration": None},
        {"compose_version": None},
        {"image": "fixture-private-tag"},
        {"container": True},
        {"unexpected": "fixture-private-db-text"},
    ],
)
def test_untyped_response_refused_without_echo(host, updates):
    with pytest.raises(generation.GenerationUnavailable) as error:
        observation(host, **updates)
    assert str(error.value) == "Compose generation observation unavailable"
    assert error.value.__cause__ is None


@pytest.mark.parametrize(
    "changes",
    [
        {"exit_code": 2},
        {"truncated": True},
        {"stderr": "fixture-private-stderr"},
        {"status": "timeout"},
    ],
)
def test_incomplete_transport_refused(host, changes):
    with pytest.raises(generation.GenerationUnavailable):
        generation.private_observation(check(**changes), host, observed_at=AT)


@pytest.mark.parametrize(
    "suffix",
    [',"image":"same"}\n', "}\n{}\n", "}\n\n", "}", ',"extra":NaN}\n', "}\r\n", "}\x00\n"],
)
def test_ambiguous_or_trailing_json_refused(host, suffix):
    result = CheckResult(name=generation.CHECK, stdout=json.dumps(RECEIPT)[:-1] + suffix)
    with pytest.raises(generation.GenerationUnavailable):
        generation.private_observation(result, host, observed_at=AT)


def test_comparison_returns_only_changes_and_unknown_provenance(host):
    first = observation(host)
    for updates, expected in (
        ({"image": "56" * 32}, ("changed", "unchanged")),
        ({"configuration": "67" * 32}, ("unchanged", "changed")),
    ):
        current = observation(host, seconds=1, container="78" * 32, **updates)
        proof = generation.compare_generation(first, current)
        assert proof.status == "observed" and proof.container == "changed"
        assert (proof.image, proof.compose_configuration) == expected
        assert proof.actor == proof.changed_at == proof.deployment_source == "unknown"
        for private in (
            SCOPE,
            current.binding,
            current.key_epoch,
            current.container,
            current.image,
            current.configuration,
            current.compose_version,
        ):
            assert private is not None and private not in proof.model_dump_json()
            assert private not in repr(current)
        assert set(current.model_dump()) == {"observed_at"}


def test_rotation_incomplete_labels_and_impossible_same_container_changes(host):
    base = observation(host)
    for updates in (
        {"compose_version": "89" * 32},
        {"compose_version": None, "configuration": None},
    ):
        current = observation(host, seconds=1, container="9a" * 32, **updates)
        result = generation.compare_generation(base, current)
        assert result.compose_configuration == "unavailable" and result.container == "changed"
    changed_registration = replace(
        host, public=host.public.model_copy(update={"trusted_hosts_digest": "9" * 64})
    )
    for current in (
        observation(host, seconds=1, image="ab" * 32),
        observation(host, seconds=1, configuration="bc" * 32),
        observation(host, seconds=1, binding="cd" * 32),
        observation(changed_registration, seconds=1),
        observation(host, seconds=-1),
    ):
        assert generation.compare_generation(base, current).status == "unavailable"
