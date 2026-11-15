# Controlled Docker restart host helper

The helper supports one explicitly registered running container on Ubuntu 24.04
with a local rootful Docker Engine and overlay2 or overlayfs storage. The
administrator enables it with a root-owned policy. The container must have no
automatic restart policy and no auto-remove setting. Compose registration
requires matching project and service labels. Standalone registration requires
both Compose labels to be absent.

Docker restarts the original full container ID. The image, writable layer,
settings and mount definitions are preserved by Docker's restart operation.
Running processes and in-memory state are interrupted. The helper observes
that the same container starts again. Business checks and data integrity
require separate verification.

## Local enrollment

Use a dedicated `opsark-container-restart` account and public key. Configure
the forced command to run `restart_ssh_entry.py` and disable password and
keyboard-interactive authentication, forwarding, PTY, user RC, and SFTP. The
account needs no Docker or other supplementary group. The intended sudoers
command is exactly

    /usr/bin/python3 -I -B /usr/local/lib/opsark-container-restart/restart_action.py

Grant only that command with `NOPASSWD` and `NOSETENV`. Verify effective
OpenSSH and sudo settings. The helper does not provision accounts or change
SSH. Install the root action, runtime and journal scripts together in the
root-owned, non-group/world-writable directory above. Native authentication
and the effective forced command need separate acceptance before release.

Create `/var/lib/opsark-container-restart` as root-owned mode 0700. Use a
root-owned mode 0600 `policy.json` with sorted compact ASCII JSON and a final
LF. `policy_digest` is SHA-256 of the JSON bytes before the LF. Required
fields are `schema_version` (1), `enabled` (true), `mode` (`assisted`),
`mode_revision`, `expires_at` (UTC seconds ending `Z`), `container_id` (64
lowercase hex digits), `image_id` (`sha256:` followed by 64 lowercase hex
digits), and `compose_project` and `compose_service` (both null for standalone).

The SSH command is `opsark-container-restart-v1`. The helper accepts one
bounded JSON request on stdin. Each request includes `schema_version`, `op`,
and `policy_digest`. Preview and explicit approval bind the exact container
and an expiring root plan. Avoid concurrent out-of-band changes to the
registered container while an approval is in flight. Docker's restart API
does not offer atomic comparison against another administrator's change.

| Operation | Other request fields |
| --- | --- |
| `prepare` | `plan_id`, `mode_revision` |
| `plan_status` | `plan_id` |
| `submit` | `plan_id`, `action_id`, `plan_digest`, `approval_id`, `mode_revision` |
| `status` or `observe` | `action_id` |
| `reconcile_status` | `plan_id`, `action_id`, `plan_digest`, `mode_revision` |

A restart consumes a durable intent before talking to the daemon. After a
disconnect, query the original action. `status` reads the root journal.
`observe` performs a separate read-only runtime observation and can verify
reconciliation after a durable original daemon acknowledgement. It preserves
the original `unknown` status. Without an acknowledgement, the outcome
stays unknown and blocks new restart plans pending administrator review.
`reconcile_status` can close an expired unstarted plan permanently. The
private history has a fixed admission limit. Automatic retirement is outside
this slice.
