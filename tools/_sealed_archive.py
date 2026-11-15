"""Closed, uncompressed USTAR envelopes for offline controller handovers."""

import hashlib
import json
import re
import tarfile
from datetime import UTC, datetime

from tools import _sealed_defense as defense

DATABASES = (
    "reports.sqlite3",
    "baselines.sqlite3",
    "security.sqlite3",
    "web-security.sqlite3",
    "security-ai.sqlite3",
    "patches.sqlite3",
    "automation.sqlite3",
    "vulnerability-watch.sqlite3",
    "automatic.sqlite3",
    "vulnerability-ai.sqlite3",
)
PROFILES = {"stores-v1", "observer-handover-v1", defense.PROFILE}
CONFIGS = {
    "compose.yaml",
    "compose.release.yaml",
    "compose.lab.yaml",
    ".env",
    "observer.env",
    "secrets/inventory.toml",
    "secrets/known_hosts",
    "secrets/patch-targets.json",
    "secrets/automation-policy.json",
    "handover.json",
}
CORE = {"stores/manifest.json", *("stores/" + name for name in DATABASES)}
IMAGE = "artifacts/controller-image.tar"
MANIFEST = "sealed-manifest.json"
MAX_IMAGE_BYTES = 1024 * 1024 * 1024
MAX_PLAINTEXT_BYTES = 1568 * 1024 * 1024
MAX_FILES = 24
HEX = re.compile(r"[0-9a-f]{64}\Z")


class ArchiveError(ValueError):
    """The fixed archive contract was not met."""


def require(condition, code):
    if not condition:
        raise ArchiveError(code)


def canonical(value):
    return (
        json.dumps(
            value, ensure_ascii=True, allow_nan=False, sort_keys=True, separators=(",", ":")
        ).encode("ascii")
        + b"\n"
    )


def strict_json(raw):
    def unique(pairs):
        value = {}
        for name, item in pairs:
            require(name not in value, "duplicate_json_field")
            value[name] = item
        return value

    def finite(_value):
        raise ArchiveError("nonfinite_json_value")

    try:
        return json.loads(raw.decode("utf-8"), object_pairs_hook=unique, parse_constant=finite)
    except (UnicodeError, ValueError, RecursionError) as error:
        raise ArchiveError("invalid_json_document") from error


def member_limit(name):
    if name == MANIFEST or name == "config-original/handover.json":
        return 65536
    if name == "stores/manifest.json":
        return 4 * 1024 * 1024
    if name in CORE:
        return 256 * 1024 * 1024
    if (
        name.startswith("config-original/")
        and name.removeprefix("config-original/") in CONFIGS | defense.CONFIGS
    ):
        return 1024 * 1024
    if name == IMAGE:
        return MAX_IMAGE_BYTES
    raise ArchiveError("unregistered_archive_member")


def handover_plan(raw, expected_profile=None):
    require(len(raw) <= 65536, "handover_record_budget")
    value = strict_json(raw)
    fields = {
        "schema_version",
        "compose_files",
        "env_files",
        "configuration_files",
        "unregistered_configuration_sources",
        "external_environment_overrides",
        "operator_confirmed_configuration_complete",
        "credential_files_included",
        "remote_root_state_included",
        "image",
    }
    v2 = (
        isinstance(value, dict)
        and type(value.get("schema_version")) is int
        and value["schema_version"] == 2
    )
    if v2:
        fields.add("ssh_defense")
    require(isinstance(value, dict) and set(value) == fields, "handover_record_schema")
    require(
        expected_profile is None
        or expected_profile == (defense.PROFILE if v2 else "observer-handover-v1"),
        "handover_profile_version",
    )
    require(
        type(value["schema_version"]) is int
        and value["schema_version"] == (2 if v2 else 1)
        and value["unregistered_configuration_sources"] is False
        and value["external_environment_overrides"] is False
        and value["operator_confirmed_configuration_complete"] is True
        and value["credential_files_included"] is False
        and value["remote_root_state_included"] is False,
        "handover_scope_incomplete",
    )
    groups = (
        (
            "compose_files",
            {"compose.yaml", "compose.release.yaml", "compose.lab.yaml"}
            | ({defense.OVERLAY} if v2 else set()),
            {"compose.yaml", "compose.release.yaml"},
        ),
        ("env_files", {".env", "observer.env"}, set()),
        (
            "configuration_files",
            {
                "secrets/inventory.toml",
                "secrets/known_hosts",
                "secrets/patch-targets.json",
                "secrets/automation-policy.json",
            }
            | ({defense.INVENTORY, defense.POLICY, *defense.PINS.values()} if v2 else set()),
            {"secrets/inventory.toml", "secrets/known_hosts"},
        ),
    )
    names = {"handover.json"}
    for field, allowed, required in groups:
        items = value[field]
        require(
            isinstance(items, list)
            and all(isinstance(x, str) for x in items)
            and len(items) == len(set(items))
            and required <= set(items) <= allowed,
            "handover_file_registration",
        )
        names.update(items)
    if v2:
        try:
            added = defense.registration(value["ssh_defense"])
        except (ValueError, TypeError):
            raise ArchiveError("handover_defense_registration") from None
        require(names & defense.CONFIGS == added, "handover_defense_member_scope")
    image = value["image"]
    require(
        isinstance(image, dict)
        and set(image) == {"image_id", "runtime_sha256", "material", "archive_sha256"}
        and isinstance(image["image_id"], str)
        and re.fullmatch(r"sha256:[0-9a-f]{64}", image["image_id"])
        and isinstance(image["runtime_sha256"], str)
        and HEX.fullmatch(image["runtime_sha256"])
        and image["material"] in {"identity_only", "embedded_archive"},
        "handover_image_identity",
    )
    if image["material"] == "embedded_archive":
        require(
            isinstance(image["archive_sha256"], str) and HEX.fullmatch(image["archive_sha256"]),
            "handover_image_archive_digest",
        )
    else:
        require(image["archive_sha256"] is None, "image_identity_is_not_an_image_backup")
    return value, names


def validate_manifest(value):
    require(
        isinstance(value, dict)
        and set(value)
        == {
            "schema_version",
            "format",
            "backup_id",
            "created_at",
            "profile",
            "quiescence",
            "credential_files_included",
            "remote_root_state_included",
            "image_material_included",
            "files",
        },
        "sealed_manifest_schema",
    )
    require(
        type(value["schema_version"]) is int
        and value["schema_version"] == (2 if value.get("profile") == defense.PROFILE else 1)
        and value["format"] == "opsark-sealed-backup"
        and isinstance(value["backup_id"], str)
        and re.fullmatch(r"sb-[0-9a-f]{32}", value["backup_id"])
        and value["profile"] in PROFILES
        and value["quiescence"] == "operator_confirmed"
        and value["credential_files_included"] is False
        and value["remote_root_state_included"] is False
        and type(value["image_material_included"]) is bool,
        "sealed_manifest_scope",
    )
    try:
        require(
            datetime.fromisoformat(value["created_at"]).utcoffset() is not None,
            "sealed_manifest_time",
        )
    except (TypeError, ValueError, OverflowError) as error:
        raise ArchiveError("sealed_manifest_time") from error
    rows = value["files"]
    require(
        isinstance(rows, list)
        and 11 <= len(rows) <= (28 if value["profile"] == defense.PROFILE else MAX_FILES),
        "sealed_member_count",
    )
    names = set()
    total = 0
    for row in rows:
        require(
            isinstance(row, dict) and set(row) == {"name", "size", "sha256", "permissions"},
            "sealed_member_schema",
        )
        name = row["name"]
        require(isinstance(name, str) and name not in names, "duplicate_archive_member")
        allowed_configs = CONFIGS | (
            defense.CONFIGS if value["profile"] == defense.PROFILE else set()
        )
        require(
            name in CORE | {IMAGE} | {"config-original/" + x for x in allowed_configs},
            "sealed_profile_member_scope",
        )
        require(
            type(row["size"]) is int
            and (0 if name.startswith("config-original/") else 1)
            <= row["size"]
            <= member_limit(name)
            and isinstance(row["sha256"], str)
            and HEX.fullmatch(row["sha256"]),
            "sealed_member_budget_or_digest",
        )
        permission = row["permissions"]
        require(
            isinstance(permission, dict) and len(canonical(permission)) <= 4096,
            "sealed_permission_record",
        )
        names.add(name)
        total += row["size"]
    require(names >= CORE and total <= MAX_PLAINTEXT_BYTES - 131072, "sealed_snapshot_scope")
    require(
        sum(x["size"] for x in rows if x["name"] in CORE - {"stores/manifest.json"})
        <= 512 * 1024 * 1024,
        "ten_store_total_budget",
    )
    if value["profile"] == "stores-v1":
        require(names == CORE and value["image_material_included"] is False, "stores_only_scope")
    else:
        require(
            "config-original/handover.json" in names
            and (IMAGE in names) == value["image_material_included"],
            "handover_members_missing",
        )
    return value


def make_manifest(backup_id, profile, rows, image_included):
    value = {
        "schema_version": 2 if profile == defense.PROFILE else 1,
        "format": "opsark-sealed-backup",
        "backup_id": backup_id,
        "created_at": datetime.now(UTC).isoformat(timespec="seconds"),
        "profile": profile,
        "quiescence": "operator_confirmed",
        "credential_files_included": False,
        "remote_root_state_included": False,
        "image_material_included": image_included,
        "files": rows,
    }
    return validate_manifest(value)


def header(name, size):
    info = tarfile.TarInfo(name)
    info.size = size
    info.mode = 0o600
    return info.tobuf(format=tarfile.USTAR_FORMAT)


def write_archive(output, manifest, sources):
    raw = canonical(manifest)
    require(len(raw) <= 65536, "sealed_manifest_budget")
    output.write(header(MANIFEST, len(raw)))
    output.write(raw)
    output.write(b"\0" * (-len(raw) % 512))
    for row in manifest["files"]:
        source = sources[row["name"]]
        source.verify()
        source.handle.seek(0)
        output.write(header(row["name"], row["size"]))
        remaining, digest = row["size"], hashlib.sha256()
        while remaining:
            chunk = source.handle.read(min(65536, remaining))
            require(bool(chunk), "source_file_truncated")
            digest.update(chunk)
            output.write(chunk)
            remaining -= len(chunk)
        require(
            not source.handle.read(1) and digest.hexdigest() == row["sha256"], "source_file_changed"
        )
        source.verify()
        output.write(b"\0" * (-row["size"] % 512))
    output.write(b"\0" * 1024)


def _exact(stream, count):
    chunks = []
    while count:
        part = stream.read(count)
        require(bool(part), "archive_truncated")
        chunks.append(part)
        count -= len(part)
    return b"".join(chunks)


def _member(raw):
    require(
        raw[257:265] == b"ustar\x0000"
        and raw[156:157] == b"0"
        and not raw[157:257].strip(b"\0")
        and not raw[345:500].strip(b"\0"),
        "only_fixed_regular_ustar_members",
    )
    for start, end in (
        (100, 108),
        (108, 116),
        (116, 124),
        (124, 136),
        (136, 148),
        (148, 156),
        (329, 337),
        (337, 345),
    ):
        require(re.fullmatch(rb"[0-7\x00 ]+", raw[start:end]), "extended_tar_number_refused")
    require(not raw[500:].strip(b"\0"), "nonzero_ustar_header_padding")
    try:
        info = tarfile.TarInfo.frombuf(raw, "ascii", "strict")
    except (tarfile.HeaderError, UnicodeError, ValueError) as error:
        raise ArchiveError("invalid_ustar_header") from error
    require(
        info.mode == 0o600
        and info.uid == info.gid == info.mtime == 0
        and not info.uname
        and not info.gname
        and info.devmajor == info.devminor == 0
        and info.size >= 0,
        "noncanonical_ustar_metadata",
    )
    return info


def extract_archive(stream, destination, paths):
    first = _member(_exact(stream, 512))
    require(first.name == MANIFEST and first.size <= 65536, "sealed_manifest_must_be_first")
    manifest = validate_manifest(strict_json(_exact(stream, first.size)))
    require(not _exact(stream, -first.size % 512).strip(b"\0"), "nonzero_archive_padding")
    expected = {row["name"]: row for row in manifest["files"]}
    seen = set()
    for _ in range(len(expected)):
        info = _member(_exact(stream, 512))
        require(info.name in expected and info.name not in seen, "unregistered_or_duplicate_member")
        row = expected[info.name]
        require(info.size == row["size"], "archive_size_mismatch")
        target = destination / info.name
        for directory in reversed(target.parent.relative_to(destination).parents):
            folder = destination / directory
            if not folder.exists():
                folder.mkdir(mode=0o700)
                paths.private_directory(folder)
        if not target.parent.exists():
            target.parent.mkdir(mode=0o700)
            paths.private_directory(target.parent)
        digest, remaining = hashlib.sha256(), info.size
        with paths.new_file(target) as output:
            while remaining:
                part = _exact(stream, min(65536, remaining))
                output.write(part)
                digest.update(part)
                remaining -= len(part)
        require(digest.hexdigest() == row["sha256"], "archive_digest_mismatch")
        require(not _exact(stream, -info.size % 512).strip(b"\0"), "nonzero_archive_padding")
        seen.add(info.name)
    require(_exact(stream, 1024) == b"\0" * 1024, "archive_end_marker_required")
    while extra := stream.read(65536):
        require(not extra.strip(b"\0"), "trailing_nonzero_archive_data")
    require(seen == set(expected), "archive_member_set_mismatch")
    if manifest["profile"] != "stores-v1":
        plan, names = handover_plan(
            (destination / "config-original/handover.json").read_bytes(), manifest["profile"]
        )
        require(
            seen
            == CORE
            | {"config-original/" + x for x in names}
            | ({IMAGE} if plan["image"]["material"] == "embedded_archive" else set()),
            "handover_member_set_mismatch",
        )
        if IMAGE in seen:
            require(
                expected[IMAGE]["sha256"] == plan["image"]["archive_sha256"],
                "image_material_digest_mismatch",
            )
        if manifest["profile"] == defense.PROFILE:
            defense.validate_bundle(
                plan,
                {name: (destination / "config-original" / name).read_bytes() for name in names},
            )
    return manifest
