"""Closed disk metadata contract shared by diagnosis and the existing AI gate."""

import hashlib
import json
import re
from typing import Annotated, Literal

from pydantic import ConfigDict, Field

from opsark.models import CheckResult, Report, StrictModel

MAX_OUTPUT = 14000
HASH = r"^[0-9a-f]{64}$"
Bytes = Annotated[int, Field(ge=0, le=2**63 - 1)]
ALLOCATION_ALGORITHM = "inode-directory-combinations/v1"
ALLOCATION_FIXED = {
    "disk_scope.total.allocated_bytes",
    "disk_scope.category.log.allocated_bytes",
    "disk_scope.category.business.allocated_bytes",
}
ALLOCATION_GROUP = re.compile(
    r"disk_scope\.group\.(log|business)\.(directory-[1-8](?:\+directory-[1-8]){0,7})"
    r"\.allocated_bytes\Z"
)


class DiskAllocationRejected(ValueError):
    """A new allocation metric or its source failed the closed baseline contract."""


class Closed(StrictModel):
    model_config = ConfigDict(extra="forbid", strict=True, frozen=True)


class DiskObject(Closed):
    object_ref: str = Field(pattern=HASH)
    directory_refs: list[str] = Field(min_length=1, max_length=8)
    category: Literal["log", "business"]
    logical_bytes: Bytes
    allocated_bytes: Bytes
    link_count: int = Field(ge=0, le=512)
    scoped_link_count: int = Field(ge=0, le=512)
    holder_refs: list[str] = Field(max_length=32)
    state: Literal["deleted_held", "linked_open", "linked_no_registered_holder"]
    release_condition: Literal[
        "business_excluded",
        "all_holders_close",
        "retention_all_links_all_holders",
        "unscoped_links_unknown",
    ]
    conditional_upper_bytes: Bytes


class DiskReclaim(Closed):
    schema_: Literal["opsark-disk-reclaim/v1"] = Field(alias="schema")
    scope_digest: str = Field(pattern=HASH)
    snapshot_atomic: Literal[False]
    holder_coverage: Literal["registered_processes_only"]
    filesystem_coverage: Literal["root_device_only"]
    physical_reclaim_verified: Literal[False]
    immediate_reclaimable_bytes: None
    conditional_lower_bytes: Literal[0]
    conditional_log_upper_bytes: Bytes
    objects: list[DiskObject] = Field(max_length=32)
    actions_enabled: Literal[False]
    snapshot_digest: str = Field(pattern=HASH)


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode("ascii")


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("Disk metadata rejected")
        result[key] = value
    return result


def _refused(_value=None):
    raise ValueError("Disk metadata rejected")


def parse_disk_reclaim(check: CheckResult, expected_scope: str | None) -> DiskReclaim:
    """No unknown field, partial/error reply or unbound projection is evidence."""
    if (
        expected_scope is None
        or check.name != "disk_reclaim"
        or check.status != "ok"
        or check.exit_code != 0
        or check.truncated
        or check.stderr
        or not 0 < len(check.stdout.encode("utf-8")) <= MAX_OUTPUT
    ):
        _refused()
    try:
        value = json.loads(check.stdout, object_pairs_hook=_pairs, parse_constant=_refused)
        if (
            type(value) is not dict
            or any(
                value.get(key) is not False
                for key in ("snapshot_atomic", "physical_reclaim_verified", "actions_enabled")
            )
            or type(value.get("conditional_lower_bytes")) is not int
        ):
            _refused()
        result = DiskReclaim.model_validate(value)
        payload = dict(value)
        payload.pop("snapshot_digest")
        if (
            result.scope_digest != expected_scope
            or result.snapshot_digest != hashlib.sha256(canonical(payload)).hexdigest()
        ):
            _refused()
        ids = set()
        for obj in result.objects:
            if (
                obj.object_ref in ids
                or obj.directory_refs != sorted(set(obj.directory_refs))
                or any(
                    ref not in {f"directory-{i}" for i in range(1, 9)} for ref in obj.directory_refs
                )
                or obj.allocated_bytes % 512
                or obj.scoped_link_count > obj.link_count
                or len(set(obj.holder_refs)) != len(obj.holder_refs)
                or any(ref not in {f"process-{i}" for i in range(1, 33)} for ref in obj.holder_refs)
            ):
                _refused()
            ids.add(obj.object_ref)
            deleted = obj.link_count == 0
            expected_state = (
                "deleted_held"
                if deleted
                else ("linked_open" if obj.holder_refs else "linked_no_registered_holder")
            )
            condition = (
                "business_excluded"
                if obj.category == "business"
                else (
                    "all_holders_close"
                    if deleted
                    else (
                        "retention_all_links_all_holders"
                        if obj.link_count == obj.scoped_link_count
                        else "unscoped_links_unknown"
                    )
                )
            )
            upper = (
                obj.allocated_bytes
                if obj.category == "log" and condition != ("unscoped_links_unknown")
                else 0
            )
            if (
                obj.state != expected_state
                or obj.release_condition != condition
                or obj.conditional_upper_bytes != upper
                or deleted
                and (obj.scoped_link_count != 0 or not obj.holder_refs)
                or not deleted
                and obj.scoped_link_count == 0
            ):
                _refused()
        if result.conditional_log_upper_bytes != sum(
            obj.conditional_upper_bytes for obj in result.objects
        ):
            _refused()
        return result
    except (ValueError, TypeError, KeyError, RecursionError):
        raise ValueError("Disk metadata rejected") from None


def safe_disk_check(check: CheckResult, expected_scope: str | None) -> tuple[CheckResult, bool]:
    try:
        result = parse_disk_reclaim(check, expected_scope)
        return check.model_copy(
            update={
                "stdout": canonical(result.model_dump(mode="json", by_alias=True)).decode("ascii")
            }
        ), False
    except ValueError:
        timed_out = check.status == "timeout"
        try:
            if len(check.stdout.encode("utf-8")) > 1024:
                _refused()
            value = json.loads(check.stdout, object_pairs_hook=_pairs, parse_constant=_refused)
            if (
                not check.truncated
                and not check.stderr
                and type(value) is dict
                and set(value) == {"schema", "reason", "actions_enabled"}
                and value["schema"] == "opsark-disk-reclaim-error/v1"
                and value["actions_enabled"] is False
                and value["reason"] == "collection_timeout"
            ):
                timed_out = True
        except (ValueError, TypeError, RecursionError):
            pass
        return check.model_copy(
            update={
                "stdout": "",
                "stderr": (
                    "磁盘元数据采集超时，未保留部分估算。"
                    if timed_out
                    else "磁盘元数据证据未通过完整白名单、范围或一致性核验。"
                ),
                "status": "timeout" if timed_out else "unavailable",
                "exit_code": None,
                "truncated": False,
            }
        ), True


def allocation_group(field: str) -> tuple[str, tuple[str, ...]] | None:
    match = ALLOCATION_GROUP.fullmatch(field)
    if match is None:
        return None
    directories = tuple(match[2].split("+"))
    if tuple(sorted(set(directories))) != directories:
        raise DiskAllocationRejected("Disk allocation metric rejected")
    return match[1], directories


def allocation_number(value: str) -> int:
    if type(value) is not str or re.fullmatch(r"0|[1-9][0-9]{0,18}", value) is None:
        raise DiskAllocationRejected("Disk allocation metric rejected")
    number = int(value)
    if number > 2**63 - 1 or number % 512:
        raise DiskAllocationRejected("Disk allocation metric rejected")
    return number


def validate_allocation_features(features: dict[str, str]) -> bool:
    """Validate the entire new metric namespace, including all accounting identities."""
    selected = {key: value for key, value in features.items() if key.startswith("disk_scope")}
    if not selected:
        return False  # Older baselines did not have this complete metadata observation.
    if selected.pop("disk_scope.algorithm", None) != ALLOCATION_ALGORITHM:
        raise DiskAllocationRejected("Disk allocation metric rejected")
    if not ALLOCATION_FIXED.issubset(selected) or len(selected) > 35:
        raise DiskAllocationRejected("Disk allocation metric rejected")
    totals = {"log": 0, "business": 0}
    for key, value in selected.items():
        number = allocation_number(value)
        group = allocation_group(key)
        if group is not None:
            totals[group[0]] += number
        elif key not in ALLOCATION_FIXED:
            raise DiskAllocationRejected("Disk allocation metric rejected")
    if any(
        allocation_number(selected[f"disk_scope.category.{category}.allocated_bytes"]) != size
        for category, size in totals.items()
    ) or allocation_number(selected["disk_scope.total.allocated_bytes"]) != sum(totals.values()):
        raise DiskAllocationRejected("Disk allocation metric rejected")
    return True


def allocation_features(result: DiskReclaim) -> dict[str, str]:
    """One inode contributes once to one category/directory-combination, never once per alias."""
    groups: dict[str, int] = {}
    totals = {"log": 0, "business": 0}
    for obj in result.objects:
        field = (
            "disk_scope.group."
            + obj.category
            + "."
            + "+".join(obj.directory_refs)
            + ".allocated_bytes"
        )
        groups[field] = groups.get(field, 0) + obj.allocated_bytes
        totals[obj.category] += obj.allocated_bytes
    features = {key: str(value) for key, value in groups.items()}
    features.update(
        {
            f"disk_scope.category.{category}.allocated_bytes": str(size)
            for category, size in totals.items()
        }
    )
    features["disk_scope.total.allocated_bytes"] = str(sum(totals.values()))
    features["disk_scope.algorithm"] = ALLOCATION_ALGORITHM
    validate_allocation_features(features)
    return features


def allocation_label(field: str) -> str | None:
    if field == "disk_scope.total.allocated_bytes":
        return "登记范围全部对象 · 已分配字节（inode 去重）"
    for category, label in (("log", "日志"), ("business", "业务数据（排除清理）")):
        if field == f"disk_scope.category.{category}.allocated_bytes":
            return label + " · 已分配字节"
    group = allocation_group(field)
    if group is None:
        return None
    category = "日志" if group[0] == "log" else "业务数据（排除清理）"
    return category + " · 登记目录组合 " + " + ".join(group[1]) + " · 已分配字节（组合只计一次）"


def validate_disk_comparison(report: Report) -> None:
    changes = [item for item in report.comparison.changes if item.field.startswith("disk_scope")]
    if not changes:
        return
    evidence = [item for item in report.evidence if item.check_id == "disk_reclaim"]
    if len(evidence) != 1 or report.target is None:
        raise DiskAllocationRejected("Disk allocation comparison rejected")
    item = evidence[0]
    projection = parse_disk_reclaim(
        CheckResult(
            name=item.check_id,
            status=item.status,
            stdout=item.output,
            exit_code=item.exit_code,
            truncated=item.truncated,
        ),
        report.target.disk_reclaim_scope_digest,
    )
    fields = allocation_features(projection)
    for change in changes:
        group = allocation_group(change.field)
        if (
            change.field not in ALLOCATION_FIXED
            and group is None
            or change.evidence_ids != [item.id]
            or change.after != fields.get(change.field, "0")
        ):
            raise DiskAllocationRejected("Disk allocation comparison rejected")
        allocation_number(change.before)
        allocation_number(change.after)
