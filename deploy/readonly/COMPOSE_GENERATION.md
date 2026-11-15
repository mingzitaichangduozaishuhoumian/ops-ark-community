# Enroll one Compose deployment for read-only generation comparison

Use a local root administrator and the reviewed deployment files under a root-owned,
non-writable staging directory. Enroll one exact Docker container name, Compose
project, and service. Use a stable container name across replacements when you want
to compare generations. This feature starts disabled.

1. Set the controller's explicit Compose generation service and scope digest for
   this managed host. Review its exported read-only policy and install it using the
   existing `opsark-readonly` procedure. The policy needs this exact no-argument
   entry. Keep the existing sudo guard and SSH account permissions.

   ```text
   LC_ALL=C timeout -k 1s 5s /usr/local/libexec/opsark-compose-generation
   ```

2. Stage the scope file locally on the target in root-owned storage. Use the
   enrolled values in compact ASCII JSON with sorted keys and one final LF. Use
   its SHA-256 to check that both hosts agree on the scope. This example uses
   synthetic values.

   ```json
   {"compose_project":"example","container_name":"example-web","schema_version":1,"service":"web"}
   ```

3. Create the target-only 32-byte binary comparison key once, from a root shell.
   The shell refuses to replace an existing file. Keep this key on the target
   with owner/group root and mode 0600. Rotating it makes previous observations
   incomparable. Use a separate key for each target.

   ```sh
   (umask 077; set -C; /usr/bin/head -c 32 /dev/urandom > /etc/opsark/compose-generation-key)
   ```

4. With the reviewed `deploy/readonly` siblings together, install from the staged
   helper directory. Supply the scope digest checked against the controller.
   Installation rechecks the exact installed policy and records the reviewed
   helper and scope digests. It leaves the key in place.

   ```sh
   /usr/bin/python3 -I -B /absolute/reviewed/deploy/readonly/install_compose_generation.py \
     --scope /absolute/staged/scope.json --expected-sha256 "$scope_digest"
   ```

The helper supports a rootful Linux Docker daemon on `/run/docker.sock` with
`/usr/bin/dockerd` and [Docker Engine API v1.44](https://docs.docker.com/reference/api/engine/version/v1.44/).
A socket created by PID 1 requires systemd's active
`docker.service` on cgroup v2. A host reboot or daemon restart breaks the
comparison binding. Validate the setup on the target before relying on a baseline.

The helper samples the enrolled container twice through Docker's filtered
container-list API. Docker's list response contains other summary fields and
labels, which remain in the target process. The helper uses only the registered
container identity, immutable image ID, and eligible Compose configuration/version
labels. It does not request full inspect, read environment variables, open Compose
files or mounted contents, or run commands inside containers. The response contains
only opaque comparison tokens. Treat tokens as private controller state. A version
outside the supported Compose v2 format leaves the configuration result unavailable.
Labels are metadata supplied when the container was created and cannot establish
who deployed it, when, or the source of its configuration.
