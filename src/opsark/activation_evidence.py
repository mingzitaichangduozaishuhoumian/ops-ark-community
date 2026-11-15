"""Read-only export of one activation and its independent observation association."""

import json
import os
import sqlite3
import stat
from contextlib import closing, contextmanager
from datetime import UTC, datetime
from pathlib import Path

from opsark.activation_store import MAX_BYTES, ActivationStore, identity
from opsark.automatic_store import canonical, digest
from opsark.vulnerability_store import collection_evidence, parse_time

MAX_BUNDLE_BYTES = 4_194_304
ERROR = "Activation evidence or read stability could not be established"


class ActivationEvidenceNotFound(LookupError):
    """Only a truly absent original identity has this outcome."""


def _require(value):
    if not value:
        raise ValueError(ERROR)


def _clean(value):
    if isinstance(value, dict):
        return {k: _clean(v) for k, v in value.items() if k not in {"owner", "claimed_by"}}
    if isinstance(value, list):
        return [_clean(v) for v in value]
    return value


def _parse(row, *, limit=MAX_BYTES):
    if row is None:
        return None
    raw = row["payload"]
    _require(isinstance(raw, str) and len(raw.encode()) <= limit)
    from opsark.vulnerability_evidence import parse_json

    value = parse_json(raw, maximum=limit)
    _require(isinstance(value, dict))
    return value


def _provenance(record, observations):
    original = record["original_job"].get("evidence_provenance")
    return {
        "original_patch": "synthetic_fixture"
        if isinstance(original, dict) and original.get("classification") == "synthetic_fixture"
        else "not_declared",
        "rescan_observations": [
            {
                "observation_id": value["id"],
                "collection_kind": value.get("collection_evidence", {}).get(
                    "collection_kind", "not_declared"
                ),
                "assessment_kind": value.get("collection_evidence", {}).get(
                    "assessment_kind", "not_declared"
                ),
            }
            for value in observations
        ],
        "internal_consistency_is_not_vendor_coverage": True,
    }


@contextmanager
def _readonly(path):
    path = Path(path).absolute()
    _require(
        not path.parent.is_symlink() and not getattr(path.parent, "is_junction", lambda: False)()
    )

    def regular():
        for entry in (path, *(Path(str(path) + suffix) for suffix in ("-wal", "-shm", "-journal"))):
            try:
                meta = entry.lstat()
            except FileNotFoundError:
                continue
            _require(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1)
            _require(not hasattr(os, "getuid") or meta.st_uid == os.getuid())
            _require(not getattr(entry, "is_junction", lambda: False)())
        _require(path.is_file())

    regular()
    before = path.stat()
    with closing(sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=2)) as connection:
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA query_only=ON")
        connection.execute("BEGIN")
        yield connection
        connection.rollback()
    regular()
    after = path.stat()
    _require((before.st_dev, before.st_ino) == (after.st_dev, after.st_ino))


def _observation(path, record, missing):
    reference = record.get("rescan_reference")
    if reference is None:
        if record["status"] == "verified":
            missing.append("activation_rescan:not_retained")
        return None, []
    _require(
        isinstance(reference, dict)
        and record["status"] == "verified"
        and reference.get("host_id") == record["host_id"]
        and reference.get("activation_id") == record["activation_id"]
        and reference.get("original_job_id") == record["job_id"]
        and reference.get("event_key") == record["activation_id"]
    )
    if path is None:
        missing.append("activation_observation_store:not_retained")
        return None, []
    with _readonly(path) as connection:
        row = connection.execute(
            "SELECT * FROM vulnerability_rescans WHERE rescan_request_id=?",
            (reference["rescan_request_id"],),
        ).fetchone()
        request = _parse(row)
        if request is None:
            missing.append("activation_rescan:not_retained")
            return None, []
        _require(
            all(
                row[key] == request.get(key)
                for key in ("rescan_request_id", "host_id", "scope_hash", "event_key", "status")
            )
        )
        _require(
            all(
                request.get(key) == reference[key]
                for key in (
                    "host_id",
                    "scope_hash",
                    "event_key",
                    "rescan_request_id",
                    "activation_id",
                    "original_job_id",
                )
            )
        )
        _require(
            request.get("job_id") is None and request.get("event_kind") == "service_activation"
        )
        _require(request.get("status") in {"pending", "claimed", "failed", "complete"})
        _require(request.get("rescan_request_id") == reference["rescan_request_id"])
        _require(
            reference["rescan_request_id"]
            == digest(
                {
                    "channel": "post-activation-rescan/v1",
                    "host_id": record["host_id"],
                    "scope_hash": reference["scope_hash"],
                    "event_key": record["activation_id"],
                    "original_job_id": record["job_id"],
                }
            )[:32]
        )
        complete = request["status"] == "complete"
        if not complete:
            missing.append("activation_rescan:" + request["status"])
        elif request.get("result_observation_id") is None or request.get("result_scan_id") is None:
            missing.append("activation_rescan_result:not_retained")
        observations = []
        for key in ("result_observation_id", "last_failure_observation_id"):
            identifier = request.get(key)
            if identifier is None or any(v.get("id") == identifier for v in observations):
                continue
            row = connection.execute(
                "SELECT payload FROM vulnerability_observations "
                "WHERE id=? AND host_id=? AND scope_hash=?",
                (identifier, record["host_id"], reference["scope_hash"]),
            ).fetchone()
            observed = _parse(row, limit=1_048_576)
            if observed is None:
                missing.append("activation_observation:not_retained")
                continue
            _require(observed.get("host_id") == record["host_id"])
            _require(observed.get("scope_hash") == reference["scope_hash"])
            _require(observed.get("id") == identifier)
            if "collection_evidence" in observed:
                collection_evidence(observed["collection_evidence"])
            if key == "result_observation_id" and complete:
                required = (
                    request.get("result_scan_id"),
                    observed.get("scan_id"),
                    observed.get("collected_at"),
                    request.get("claimed_at"),
                    request.get("requested_at"),
                    request.get("completed_at"),
                )
                if any(value is None for value in required):
                    missing.append("activation_observation_binding:not_retained")
                else:
                    identity(record["host_id"], request["result_scan_id"])
                    identity(record["host_id"], observed["id"])
                    _require(observed["scan_id"] == request["result_scan_id"])
                    _require(observed["status"] in {"partial", "complete"})
                    collected = parse_time(observed["collected_at"])
                    _require(collected >= parse_time(request["requested_at"]))
                    _require(collected >= parse_time(request["claimed_at"]))
                    _require(
                        parse_time(request["completed_at"]) >= parse_time(request["claimed_at"])
                    )
                    if record.get("result", {}).get("completed_at") is not None:
                        _require(collected >= parse_time(record["result"]["completed_at"]))
            observations.append(observed)
        return _clean(request), _clean(observations)


def _collect(service, host_id, activation_id, exported_at):
    with _readonly(service.store.path) as connection:
        row = connection.execute(
            "SELECT * FROM service_activation_records WHERE host_id=? AND activation_id=?",
            (host_id, activation_id),
        ).fetchone()
        if row is None:
            raise ActivationEvidenceNotFound("Activation evidence is not retained")
        record = ActivationStore._read(row)
        _require(
            record["plan"]["activation_digest"]
            == digest({k: v for k, v in record["plan"].items() if k != "activation_digest"})
        )
        _require(record["original_job"].get("status") == "installed_restart_pending")
        _require(digest(record["original_job"]) == record["job_digest"])
        from opsark.activation_api import ActivationService
        from opsark.patch_client import PatchClientError

        try:
            ActivationService.validate_cached(record)
        except PatchClientError:
            raise ValueError(ERROR) from None
        cached = _parse(
            connection.execute(
                "SELECT payload FROM patch_jobs WHERE host_id=? AND job_id=?",
                (host_id, record["job_id"]),
            ).fetchone()
        )
        if cached is not None:
            _require(cached.get("status") == "installed_restart_pending")
            _require(digest(cached) == record["job_digest"])
    missing = []
    if record["submitted_at"] is not None and record["result"] is None:
        missing.append("root_activation_result:not_retained")
    observation_store = service.evidence_observation_store
    request, observations = _observation(
        observation_store.path if observation_store is not None else None, record, missing
    )
    body = {
        "schema_version": 1,
        "kind": "opsark-service-activation-evidence",
        "exported_at": exported_at,
        "read_only": True,
        "actions_executable": False,
        "origin_authenticity": "not_authenticated",
        "identity": {
            "host_id": host_id,
            "activation_id": activation_id,
            "original_job_id": record["job_id"],
        },
        "activation_record": _clean(record),
        "original_patch_job": _clean(record["original_job"]),
        "cached_original_patch_job": _clean(cached),
        "rescan_request": request,
        "observations": observations,
        "missing_components": missing,
        "original_patch_status": "installed_restart_pending",
        "evidence_provenance": _provenance(record, observations),
        "evidence_status": "incomplete" if missing else "internally_consistent",
        "operation_status": record["status"],
    }
    _require(len(canonical(body).encode()) <= MAX_BUNDLE_BYTES)
    return body


def build_evidence(service, host_id, activation_id):
    """Read original database rows twice; never resolve settings or contact a target."""
    identity(host_id, activation_id)
    exported_at = datetime.now(UTC).isoformat()
    for _attempt in range(2):
        first = _collect(service, host_id, activation_id, exported_at)
        second = _collect(service, host_id, activation_id, exported_at)
        if canonical(first) == canonical(second):
            second["bundle_digest"] = digest(second)
            _require(len(canonical(second).encode()) <= MAX_BUNDLE_BYTES)
            return json.loads(canonical(second))
    raise ValueError(ERROR)


def verify_bundle(bundle):
    """Offline internal checks only; no store, SSH, settings, model or signature claim."""
    from opsark.activation_api import ActivationService

    try:
        _require(
            isinstance(bundle, dict) and bundle.get("kind") == "opsark-service-activation-evidence"
        )
        _require(type(bundle.get("schema_version")) is int and bundle["schema_version"] == 1)
        _require(bundle.get("read_only") is True and bundle.get("actions_executable") is False)
        _require(bundle.get("origin_authenticity") == "not_authenticated")
        _require(
            bundle["bundle_digest"]
            == digest({k: v for k, v in bundle.items() if k != "bundle_digest"})
        )
        record, original = bundle["activation_record"], bundle["original_patch_job"]
        ActivationService.validate_cached(record)
        _require(
            bundle["identity"]
            == {
                "host_id": record["host_id"],
                "activation_id": record["activation_id"],
                "original_job_id": record["job_id"],
            }
        )
        _require(original == record["original_job"] and digest(original) == record["job_digest"])
        _require(
            original["status"] == bundle["original_patch_status"] == "installed_restart_pending"
        )
        _require(bundle["operation_status"] == record["status"])
        cached = bundle.get("cached_original_patch_job")
        _require(cached is None or cached == original)
        missing = bundle["missing_components"]
        _require(isinstance(missing, list) and all(isinstance(v, str) for v in missing))
        _require(
            bundle["evidence_status"] == ("incomplete" if missing else "internally_consistent")
        )
        request, observations = bundle["rescan_request"], bundle["observations"]
        _require(isinstance(observations, list) and len(observations) <= 2)
        if "evidence_provenance" in bundle:
            _require(bundle["evidence_provenance"] == _provenance(record, observations))
        reference = record.get("rescan_reference")
        if request is None:
            _require(not observations)
            if record["status"] == "verified":
                _require(bool(missing))
        else:
            _require(record["status"] == "verified" and isinstance(reference, dict))
            _require(
                all(
                    request.get(k) == reference[k]
                    for k in (
                        "host_id",
                        "activation_id",
                        "original_job_id",
                        "scope_hash",
                        "event_key",
                        "rescan_request_id",
                    )
                )
            )
            _require(request["activation_id"] == record["activation_id"] == request["event_key"])
            _require(
                request["original_job_id"] == record["job_id"] and request.get("job_id") is None
            )
            _require(request["event_kind"] == "service_activation")
            _require(
                request["rescan_request_id"]
                == digest(
                    {
                        "channel": "post-activation-rescan/v1",
                        "host_id": record["host_id"],
                        "scope_hash": reference["scope_hash"],
                        "event_key": record["activation_id"],
                        "original_job_id": record["job_id"],
                    }
                )[:32]
            )
            _require(request["status"] in {"pending", "claimed", "failed", "complete"})
            if request["status"] != "complete":
                _require("activation_rescan:" + request["status"] in missing)
            ids = set()
            for observed in observations:
                _require(observed["id"] not in ids)
                ids.add(observed["id"])
                _require(
                    observed["host_id"] == record["host_id"]
                    and observed["scope_hash"] == reference["scope_hash"]
                )
                _require(
                    observed["id"]
                    in {
                        request.get("result_observation_id"),
                        request.get("last_failure_observation_id"),
                    }
                )
                if "collection_evidence" in observed:
                    collection_evidence(observed["collection_evidence"])
                if (
                    observed["id"] == request.get("result_observation_id")
                    and request["status"] == "complete"
                ):
                    if any(
                        value is None
                        for value in (
                            request.get("result_scan_id"),
                            observed.get("scan_id"),
                            observed.get("collected_at"),
                            request.get("claimed_at"),
                            request.get("completed_at"),
                        )
                    ):
                        _require(bool(missing))
                    else:
                        identity(record["host_id"], request["result_scan_id"])
                        identity(record["host_id"], observed["id"])
                        _require(observed["scan_id"] == request["result_scan_id"])
                        _require(observed["status"] in {"partial", "complete"})
                        _require(
                            parse_time(observed["collected_at"])
                            >= parse_time(request["requested_at"])
                        )
                        _require(
                            parse_time(observed["collected_at"])
                            >= parse_time(request["claimed_at"])
                        )
                        _require(
                            parse_time(request["completed_at"]) >= parse_time(request["claimed_at"])
                        )
                        _require(
                            parse_time(observed["collected_at"])
                            >= parse_time(record["result"]["completed_at"])
                        )
            if request["status"] == "complete" and request.get("result_observation_id") not in ids:
                _require(bool(missing))
        return {
            "valid": not missing,
            "integrity_valid": True,
            "status": bundle["evidence_status"],
            "operation_status": record["status"],
            "observation_count": len(observations),
            "missing_components": missing,
            "origin_authenticity": "not_authenticated",
            "internal_consistency_is_not_vendor_coverage": True,
            "evidence_provenance": _provenance(record, observations),
        }
    except Exception:
        return {
            "valid": False,
            "status": "invalid",
            "error": ERROR,
            "origin_authenticity": "not_authenticated",
        }


def main():
    import sys

    from opsark.vulnerability_evidence import parse_json

    try:
        _require(len(sys.argv) == 2)
        with Path(sys.argv[1]).open("rb") as source:
            raw = source.read(MAX_BUNDLE_BYTES + 1)
        report = verify_bundle(parse_json(raw, maximum=MAX_BUNDLE_BYTES))
    except Exception:
        report = {
            "valid": False,
            "status": "invalid",
            "error": ERROR,
            "origin_authenticity": "not_authenticated",
        }
    print(json.dumps(report, ensure_ascii=True, allow_nan=False))
    return 0 if report["valid"] else 2
