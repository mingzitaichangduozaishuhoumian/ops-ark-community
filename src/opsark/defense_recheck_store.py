"""Independent v2 business recheck intents and sealed results in security.sqlite3.

Claiming permits one read-only collection attempt, never a Root mutation. A lost
claim stays unfinished across restart and cannot be replayed or automatically reclaimed.
"""

import hashlib
import json
import secrets
from datetime import datetime, timedelta

from pydantic import TypeAdapter

from opsark.defense_models import (
    ActionBody,
    Digest,
    Identifier,
    PrepareBody,
    canonical,
    digest,
    utc,
)
from opsark.defense_recheck_models import (
    ActionBusinessProfile,
    DefenseRecheckDeclaration,
    DefenseRecheckResult,
    DefenseRecheckRun,
    RecheckAuthority,
    RecheckClaim,
    RecheckInterruption,
    RecheckRootEvidence,
)
from opsark.defense_store import DefenseConflict, DefenseStore, Host, Owner, _now, _stamp

HARD_RECHECK_BUDGET_SECONDS = 120


def _hash(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def _typed(model, raw: bytes, expected_sha256: str, *, limit=32768):
    if type(raw) is not bytes or not 0 < len(raw) <= limit or _hash(raw) != expected_sha256:
        raise DefenseConflict("Defense recheck stored object integrity failed")

    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise ValueError("Duplicate defense recheck field")
            result[key] = value
        return result

    def nonfinite(_value):
        raise ValueError("Nonfinite defense recheck value")

    try:
        document = json.loads(raw, object_pairs_hook=unique, parse_constant=nonfinite)
        return model.model_validate_json(canonical(document))
    except (ValueError, TypeError, RecursionError):
        raise DefenseConflict("Defense recheck stored schema validation failed") from None


class DefenseRecheckStore:
    def __init__(self, base: DefenseStore):
        if type(base) is not DefenseStore:
            raise TypeError("Defense rechecks require the existing defense ledger")
        self.base, self.path = base, base.path
        with base._connection() as connection:
            connection.executescript("""
                CREATE TABLE IF NOT EXISTS defense_action_business_profiles_v1(
                    rid TEXT PRIMARY KEY REFERENCES defense_transactions(rid),
                    profile_sha256 TEXT NOT NULL, typed_profile BLOB NOT NULL
                );
                CREATE TABLE IF NOT EXISTS defense_recheck_runs_v2(
                    sequence INTEGER PRIMARY KEY AUTOINCREMENT,
                    run_ref TEXT NOT NULL UNIQUE,
                    host_id TEXT NOT NULL, rid TEXT NOT NULL REFERENCES defense_transactions(rid),
                    declaration_sha256 TEXT NOT NULL, typed_declaration BLOB NOT NULL,
                    status TEXT NOT NULL
                        CHECK(status IN ('pending','claimed','completed','interrupted')),
                    created_at TEXT NOT NULL, claimed_at TEXT, owner TEXT,
                    claim_sha256 TEXT, typed_claim BLOB,
                    interruption_sha256 TEXT, typed_interruption BLOB
                );
                CREATE TABLE IF NOT EXISTS defense_recheck_results_v2(
                    run_ref TEXT PRIMARY KEY REFERENCES defense_recheck_runs_v2(run_ref),
                    result_sha256 TEXT NOT NULL, typed_result BLOB NOT NULL
                );
            """)
            columns = {
                row["name"]
                for row in connection.execute("PRAGMA table_info(defense_recheck_runs_v2)")
            }
            for name in ("interruption_sha256", "typed_interruption"):
                if name not in columns:
                    connection.execute(f"ALTER TABLE defense_recheck_runs_v2 ADD COLUMN {name}")  # noqa: S608 -- fixed own columns.
            index = connection.execute(
                "SELECT sql FROM sqlite_master WHERE name='defense_recheck_one_claimed_host_v2'"
            ).fetchone()
            if index is not None and "typed_interruption IS NULL" not in index[0]:
                connection.execute("DROP INDEX IF EXISTS defense_recheck_one_claimed_host_v2")
            connection.execute(
                "CREATE UNIQUE INDEX IF NOT EXISTS defense_recheck_one_claimed_host_v2 "
                "ON defense_recheck_runs_v2(host_id) "
                "WHERE status='claimed' AND typed_interruption IS NULL"
            )
            sql = connection.execute(
                "SELECT sql FROM sqlite_master WHERE name='defense_recheck_runs_v2'"
            ).fetchone()[0]
            self._interrupted_status = "interrupted" if "'interrupted'" in sql else "claimed"

    def _profile(self, connection, rid: str) -> ActionBusinessProfile | None:
        row = connection.execute(
            "SELECT * FROM defense_action_business_profiles_v1 WHERE rid=?", (rid,)
        ).fetchone()
        if row is None:
            return None
        profile = _typed(
            ActionBusinessProfile, row["typed_profile"], row["profile_sha256"], limit=4096
        )
        transaction = self.base._transaction(connection, rid)
        request = self.base._request(connection, rid, "prepare")
        sent = connection.execute(
            "SELECT send_started_at FROM defense_requests WHERE rid=? AND op='prepare'", (rid,)
        ).fetchone()
        if (
            profile.rid != rid
            or transaction.kind != "action"
            or profile.context_sha256 != digest(transaction.context)
            or profile.prepare_request_sha256 != _hash(request.wire_bytes())
            or not isinstance(request.body, PrepareBody)
            or utc(profile.sealed_at) < utc(transaction.created_at)
            or (
                sent is not None
                and sent["send_started_at"] is not None
                and utc(profile.sealed_at) > utc(sent["send_started_at"])
            )
        ):
            raise DefenseConflict("Defense original business profile binding changed")
        return profile

    def action_profile(self, rid: str) -> ActionBusinessProfile | None:
        TypeAdapter(Identifier).validate_python(rid, strict=True)
        with self.base._connection() as connection:
            self.base._transaction(connection, rid)
            return self._profile(connection, rid)

    def seal_action_profile(self, profile: ActionBusinessProfile) -> ActionBusinessProfile:
        if type(profile) is not ActionBusinessProfile:
            raise TypeError("Defense profiles must be server-typed objects")
        profile = ActionBusinessProfile.model_validate_json(canonical(profile))
        with self.base._write() as connection:
            previous = self._profile(connection, profile.rid)
            if previous is not None:
                if previous != profile:
                    raise DefenseConflict("Defense original business profile cannot be replaced")
                return previous
            row = connection.execute(
                "SELECT dispatch_phase,send_started_at FROM defense_requests "
                "WHERE rid=? AND op='prepare'",
                (profile.rid,),
            ).fetchone()
            if (
                row is None
                or row["dispatch_phase"] != "intent"
                or row["send_started_at"] is not None
            ):
                raise DefenseConflict(
                    "Defense business profile cannot be added after prepare dispatch"
                )
            connection.execute(
                "INSERT INTO defense_action_business_profiles_v1 VALUES(?,?,?)",
                (profile.rid, digest(profile), canonical(profile)),
            )
            actual = self._profile(connection, profile.rid)
            if actual is None:
                raise DefenseConflict("Defense original business profile was not retained")
            return actual

    def authority(self, rid: str, root: RecheckRootEvidence | None = None) -> RecheckAuthority:
        def unproven(reason):
            return RecheckAuthority(kind="unproven", proof_sha256=None, reason_codes=(reason,))

        try:
            transaction = self.base.transaction(rid)
            prepare = self.base.request(rid, "prepare")
            manifest = self.base.manifest(rid)
            apply = self.base.request(rid, "apply")
            prepare_meta, apply_meta = (
                self.base.request_metadata(rid, "prepare"),
                self.base.request_metadata(rid, "apply"),
            )
            if (
                transaction.kind != "action"
                or not isinstance(prepare.body, PrepareBody)
                or not isinstance(apply.body, ActionBody)
                or apply.body.manifest_sha256 != manifest.sha256
                or manifest.controller_grant_ref != prepare.body.controller_grant_ref
                or manifest.root_grant_ref != prepare.body.root_grant_ref
                or manifest.mode != prepare.body.mode
                or manifest.mode != transaction.context.mode
                or manifest.mode_revision != transaction.context.wire_revision
                or prepare_meta.send_started_at is None
                or apply_meta.send_started_at is None
                or apply_meta.send_owner != transaction.owner
                or prepare_meta.send_owner != transaction.owner
                or apply_meta.dispatch_phase not in {"sendable", "replied", "unknown"}
                or not utc(transaction.created_at)
                <= utc(prepare_meta.send_started_at)
                <= utc(apply_meta.send_started_at)
                < utc(transaction.deadline_at)
            ):
                return unproven("apply_not_sent")
            usage = self.base.execution_usage(rid)
            if (
                usage is None
                or usage.state not in {"consumed", "unknown"}
                or utc(usage.created_at) > utc(prepare_meta.send_started_at)
            ):
                return unproven("usage_missing")
            identity = {
                "channel": "ssh-defense-recheck-authority/v2",
                "rid": rid,
                "context_sha256": digest(transaction.context),
                "prepare_request_sha256": prepare_meta.request_sha256,
                "manifest_sha256": manifest.sha256,
                "apply_request_sha256": apply_meta.request_sha256,
                "send_owner": apply_meta.send_owner,
                "send_started_at": apply_meta.send_started_at,
                "execution_usage": usage.model_dump(exclude={"state"}, mode="json"),
            }
            if apply.body.approval is not None:
                record = self.base.approval_record(rid, "apply")
                if record is None:
                    return unproven("approval_missing")
                if record.dispatch_state != "used":
                    return unproven("approval_unused")
                if (
                    transaction.context.mode != "semi"
                    or record.metadata.approval != apply.body.approval
                ):
                    return unproven("approval_invalid")
                identity["kind"] = "human_approval"
                identity["approval"] = record.model_dump(mode="json")
                return RecheckAuthority(
                    kind="human_approval",
                    proof_sha256=digest(identity),
                    reason_codes=("authority_proven",),
                )
            if transaction.context.mode != "auto":
                return unproven("preauthorization_invalid")
            if (
                root is None
                or not root.observation.accepted
                or root.reply is None
                or root.reply.state not in {"active", "expired", "revoked"}
            ):
                return unproven("root_unproven")
            exact = self.base.observation_record(root.observation.observation_id)
            if canonical(exact) != canonical(root) or root.observation.rid != rid:
                return unproven("root_unproven")
            identity["kind"] = "preauthorization"
            return RecheckAuthority(
                kind="preauthorization",
                proof_sha256=digest(identity),
                reason_codes=("authority_proven",),
            )
        except (ValueError, TypeError, KeyError, AttributeError):
            return unproven("authority_unproven")

    def _result(self, connection, row, declaration, claim):
        saved = connection.execute(
            "SELECT * FROM defense_recheck_results_v2 WHERE run_ref=?", (declaration.run_ref,)
        ).fetchone()
        if saved is None:
            return None, None
        result = _typed(DefenseRecheckResult, saved["typed_result"], saved["result_sha256"])
        self._validate_result(connection, declaration, claim, result)
        return result, saved["result_sha256"]

    def _run(self, connection, row) -> DefenseRecheckRun:
        declaration = _typed(
            DefenseRecheckDeclaration,
            row["typed_declaration"],
            row["declaration_sha256"],
            limit=4096,
        )
        if (
            declaration.run_ref != row["run_ref"]
            or declaration.host_id != row["host_id"]
            or declaration.rid != row["rid"]
        ):
            raise DefenseConflict("Defense recheck declaration references changed")
        transaction = self.base._transaction(connection, declaration.rid)
        if transaction.context.host_id != declaration.host_id or transaction.kind != "action":
            raise DefenseConflict("Defense recheck original action changed")
        claim = None
        if row["typed_claim"] is not None:
            claim = _typed(RecheckClaim, row["typed_claim"], row["claim_sha256"], limit=4096)
        elif row["claim_sha256"] is not None:
            raise DefenseConflict("Defense recheck claim bytes are missing")
        result, result_sha256 = self._result(connection, row, declaration, claim)
        interruption = None
        if row["typed_interruption"] is not None:
            interruption = _typed(
                RecheckInterruption,
                row["typed_interruption"],
                row["interruption_sha256"],
                limit=4096,
            )
            if (
                row["status"] not in {"claimed", "interrupted"}
                or claim is None
                or interruption.claim_ref != claim.claim_ref
                or interruption.hard_deadline_at
                != _stamp(utc(claim.claimed_at) + timedelta(seconds=HARD_RECHECK_BUDGET_SECONDS))
                or utc(interruption.interrupted_at) < utc(interruption.hard_deadline_at)
                or utc(interruption.interrupted_at) < utc(row["created_at"])
            ):
                raise DefenseConflict("Defense recheck interruption metadata changed")
        elif row["interruption_sha256"] is not None:
            raise DefenseConflict("Defense recheck interruption bytes are missing")
        return DefenseRecheckRun(
            sequence=row["sequence"],
            declaration=declaration,
            declaration_sha256=row["declaration_sha256"],
            status="interrupted" if interruption is not None else row["status"],
            created_at=row["created_at"],
            claimed_at=row["claimed_at"],
            owner=row["owner"],
            claim=claim,
            result_sha256=result_sha256,
            result=result,
            interruption=interruption,
        )

    def get(self, run_ref: str) -> DefenseRecheckRun | None:
        TypeAdapter(Identifier).validate_python(run_ref, strict=True)
        with self.base._connection() as connection:
            row = connection.execute(
                "SELECT * FROM defense_recheck_runs_v2 WHERE run_ref=?", (run_ref,)
            ).fetchone()
            return None if row is None else self._run(connection, row)

    def active_run(self, host_id: str) -> DefenseRecheckRun | None:
        TypeAdapter(Host).validate_python(host_id, strict=True)
        with self.base._connection() as connection:
            row = connection.execute(
                "SELECT * FROM defense_recheck_runs_v2 WHERE host_id=? AND status='claimed' "
                "AND typed_interruption IS NULL "
                "ORDER BY sequence LIMIT 1",
                (host_id,),
            ).fetchone()
            return None if row is None else self._run(connection, row)

    def create(
        self, declaration: DefenseRecheckDeclaration, *, now: datetime | None = None
    ) -> DefenseRecheckRun:
        if type(declaration) is not DefenseRecheckDeclaration:
            raise TypeError("Defense recheck declarations must be server-typed objects")
        declaration = DefenseRecheckDeclaration.model_validate_json(canonical(declaration))
        with self.base._write() as connection:
            old = connection.execute(
                "SELECT * FROM defense_recheck_runs_v2 WHERE run_ref=?", (declaration.run_ref,)
            ).fetchone()
            if old is not None:
                if old["declaration_sha256"] != declaration.sha256:
                    raise DefenseConflict(
                        "Defense recheck run reference belongs to a different declaration"
                    )
                return self._run(connection, old)
            transaction = self.base._transaction(connection, declaration.rid)
            profile = self._profile(connection, declaration.rid)
            if (
                transaction.kind != "action"
                or transaction.context.host_id != declaration.host_id
                or transaction.manifest_sha256 not in {None, declaration.expected_manifest_sha256}
                or (
                    profile is not None
                    and profile.business_profile_sha256 != declaration.expected_profile_sha256
                )
            ):
                raise DefenseConflict(
                    "Defense recheck declaration does not match the original action"
                )
            connection.execute(
                "INSERT INTO defense_recheck_runs_v2(run_ref,host_id,rid,declaration_sha256,"
                "typed_declaration,status,created_at) "
                "VALUES(?,?,?,?,?,'pending',?)",
                (
                    declaration.run_ref,
                    declaration.host_id,
                    declaration.rid,
                    declaration.sha256,
                    canonical(declaration),
                    _stamp(_now(now)),
                ),
            )
            row = connection.execute(
                "SELECT * FROM defense_recheck_runs_v2 WHERE run_ref=?", (declaration.run_ref,)
            ).fetchone()
            return self._run(connection, row)

    def claim(
        self, run_ref: str, *, owner: str, now: datetime | None = None
    ) -> RecheckClaim | None:
        TypeAdapter(Identifier).validate_python(run_ref, strict=True)
        TypeAdapter(Owner).validate_python(owner, strict=True)
        with self.base._write() as connection:
            row = connection.execute(
                "SELECT * FROM defense_recheck_runs_v2 WHERE run_ref=?", (run_ref,)
            ).fetchone()
            if row is None:
                raise DefenseConflict("Defense recheck run was not found")
            original = self._run(connection, row)
            if original.status != "pending":
                return None
            active = connection.execute(
                "SELECT 1 FROM defense_recheck_runs_v2 WHERE host_id=? AND status='claimed' "
                "AND typed_interruption IS NULL",
                (row["host_id"],),
            ).fetchone()
            if active is not None:
                raise DefenseConflict("Defense host already has an unfinished recheck")
            latest = connection.execute(
                "SELECT COALESCE(MAX(rowid),0) AS sequence FROM defense_observations WHERE rid=?",
                (row["rid"],),
            ).fetchone()
            claim = RecheckClaim(
                run_ref=run_ref,
                sequence=row["sequence"],
                owner=owner,
                claim_ref=secrets.token_hex(16),
                claimed_at=_stamp(_now(now)),
                declaration_sha256=row["declaration_sha256"],
                observation_sequence=latest["sequence"],
            )
            connection.execute(
                "UPDATE defense_recheck_runs_v2 SET status='claimed',claimed_at=?,owner=?,"
                "claim_sha256=?,typed_claim=? WHERE run_ref=? AND status='pending'",
                (claim.claimed_at, owner, digest(claim), canonical(claim), run_ref),
            )
            return claim

    def _validate_result(self, connection, declaration, claim, result, *, live=False):
        if claim is None:
            raise DefenseConflict("Defense recheck result has no original collection claim")
        transaction = self.base._transaction(connection, declaration.rid)
        profile = self._profile(connection, declaration.rid)
        if (
            result.run_ref != declaration.run_ref
            or result.host_id != declaration.host_id
            or result.rid != declaration.rid
            or result.manifest_sha256 != declaration.expected_manifest_sha256
            or result.business_profile_sha256 != declaration.expected_profile_sha256
            or result.defense_scope != transaction.context.defense_scope
            or (
                result.verdict == "passed" and result.manifest_sha256 != transaction.manifest_sha256
            )
        ):
            raise DefenseConflict("Defense recheck result declaration binding changed")
        for root in (result.root_before, result.root_after):
            if root is not None:
                exact = self.base.observation_record(root.observation.observation_id)
                if (
                    canonical(exact) != canonical(root)
                    or root.sequence <= claim.observation_sequence
                ):
                    raise DefenseConflict("Defense recheck result did not use its own exact query")
        if result.authority.kind != "unproven" and result.authority != self.authority(
            result.rid, result.root_before
        ):
            raise DefenseConflict("Defense recheck authority proof changed")
        if (
            result.root_before is not None
            and result.root_after is not None
            and result.root_after.sequence <= result.root_before.sequence
        ):
            raise DefenseConflict(
                "Defense recheck after query must be a distinct later observation"
            )
        if profile is not None:
            if result.host_scope != profile.host_scope:
                raise DefenseConflict("Defense recheck host scope changed")
            if result.verdict == "passed" and (
                result.business_profile_sha256 != profile.business_profile_sha256
                or tuple(check.id for check in result.business.checks) != profile.check_ids
            ):
                raise DefenseConflict(
                    "Defense recheck does not cover the original business profile"
                )
        if result.verdict == "passed" and (
            profile is None
            or transaction.manifest_sha256 is None
            or utc(result.started_at) < utc(claim.claimed_at)
        ):
            raise DefenseConflict("Defense recheck passing evidence is incomplete")
        if result.verdict == "passed":
            row = connection.execute(
                "SELECT created_at FROM defense_recheck_runs_v2 WHERE run_ref=?",
                (declaration.run_ref,),
            ).fetchone()
            if row is None or utc(claim.claimed_at) < utc(row["created_at"]):
                raise DefenseConflict("Defense recheck clock regressed before its collection claim")
            if live:
                latest = self.base.latest_observation(result.rid)
                if (
                    latest is None
                    or result.root_after is None
                    or latest.sequence != result.root_after.sequence
                ):
                    raise DefenseConflict(
                        "Defense recheck current Root evidence changed before sealing"
                    )

    def interrupt(
        self, run_ref: str, *, expected_declaration_sha256: str, now: datetime
    ) -> DefenseRecheckRun:
        TypeAdapter(Identifier).validate_python(run_ref, strict=True)
        TypeAdapter(Digest).validate_python(expected_declaration_sha256, strict=True)
        instant = _now(now)
        with self.base._write() as connection:
            row = connection.execute(
                "SELECT * FROM defense_recheck_runs_v2 WHERE run_ref=?", (run_ref,)
            ).fetchone()
            if row is None:
                raise DefenseConflict("Defense recheck run was not found")
            original = self._run(connection, row)
            if original.declaration_sha256 != expected_declaration_sha256:
                raise DefenseConflict("Defense recheck recovery declaration changed")
            if original.status == "interrupted":
                return original
            if original.status != "claimed" or original.claim is None:
                raise DefenseConflict("Defense recheck is not an unfinished claimed collection")
            deadline = utc(original.claim.claimed_at) + timedelta(
                seconds=HARD_RECHECK_BUDGET_SECONDS
            )
            if (
                utc(original.claim.claimed_at) < utc(original.created_at)
                or instant < deadline
                or instant < utc(original.created_at)
            ):
                raise DefenseConflict("Defense recheck collection hard budget has not elapsed")
            interruption = RecheckInterruption(
                interrupted_at=_stamp(instant),
                hard_deadline_at=_stamp(deadline),
                reason_code="collection_deadline_elapsed",
                claim_ref=original.claim.claim_ref,
                declaration_sha256=original.declaration_sha256,
            )
            # Pre-release v2 databases may have the original three-value CHECK.
            # Their explicit interruption marker closes the logical claim while
            # retaining its original SQL phase; the host index excludes that marker.
            connection.execute(
                "UPDATE defense_recheck_runs_v2 SET status=?,interruption_sha256=?,"
                "typed_interruption=? "
                "WHERE run_ref=? AND typed_interruption IS NULL",
                (self._interrupted_status, digest(interruption), canonical(interruption), run_ref),
            )
            row = connection.execute(
                "SELECT * FROM defense_recheck_runs_v2 WHERE run_ref=?", (run_ref,)
            ).fetchone()
            return self._run(connection, row)

    def finish(self, claim: RecheckClaim, result: DefenseRecheckResult) -> DefenseRecheckRun:
        if type(claim) is not RecheckClaim or type(result) is not DefenseRecheckResult:
            raise TypeError("Defense recheck results must be server-typed objects")
        claim = RecheckClaim.model_validate_json(canonical(claim))
        result = DefenseRecheckResult.model_validate_json(canonical(result))
        with self.base._write() as connection:
            row = connection.execute(
                "SELECT * FROM defense_recheck_runs_v2 WHERE run_ref=?", (claim.run_ref,)
            ).fetchone()
            if row is None:
                raise DefenseConflict("Defense recheck run was not found")
            original = self._run(connection, row)
            if original.claim != claim:
                raise DefenseConflict("Defense recheck collection owner changed")
            if original.status == "completed":
                if original.result != result:
                    raise DefenseConflict("Defense recheck sealed result cannot be replaced")
                return original
            if original.status != "claimed":
                raise DefenseConflict("Defense recheck has no active original claim")
            self._validate_result(connection, original.declaration, claim, result, live=True)
            connection.execute(
                "INSERT INTO defense_recheck_results_v2 VALUES(?,?,?)",
                (claim.run_ref, digest(result), canonical(result)),
            )
            connection.execute(
                "UPDATE defense_recheck_runs_v2 SET status='completed' WHERE run_ref=?",
                (claim.run_ref,),
            )
            row = connection.execute(
                "SELECT * FROM defense_recheck_runs_v2 WHERE run_ref=?", (claim.run_ref,)
            ).fetchone()
            return self._run(connection, row)

    def list(
        self, host_id: str, rid: str | None = None, *, after_sequence: int = 0, limit: int = 20
    ) -> tuple[DefenseRecheckRun, ...]:
        TypeAdapter(Host).validate_python(host_id, strict=True)
        if rid is not None:
            TypeAdapter(Identifier).validate_python(rid, strict=True)
        if (
            type(after_sequence) is not int
            or not 0 <= after_sequence <= 2**63 - 1
            or type(limit) is not int
            or not 1 <= limit <= 100
        ):
            raise ValueError("Defense recheck page bounds are invalid")
        with self.base._connection() as connection:
            rows = connection.execute(
                "SELECT * FROM defense_recheck_runs_v2 WHERE host_id=? AND (? IS NULL OR rid=?) "
                "AND sequence>? ORDER BY sequence LIMIT ?",
                (host_id, rid, rid, after_sequence, limit),
            ).fetchall()
            return tuple(self._run(connection, row) for row in rows)
