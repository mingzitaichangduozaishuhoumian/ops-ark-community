#!/usr/bin/env python3
"""Apply one reviewed Nginx fixture change and verify its isolated Docker runtime."""

import hashlib
import json
import os
import re
import signal
import stat
import subprocess
import sys
import time
from contextlib import closing
from pathlib import Path
from tempfile import TemporaryDirectory

if not __package__:
    entry = Path(__file__).absolute()
    for path in (entry, *entry.parents):
        info = path.lstat()
        if (
            info.st_uid != 0
            or info.st_mode & 0o022
            or not (stat.S_ISREG(info.st_mode) if path == entry else stat.S_ISDIR(info.st_mode))
        ):
            raise SystemExit("An administrator-owned tool installation is required.")
    sys.path.insert(0, str(entry.parents[2]))

from deploy.nginx import (  # noqa: E402 -- trusted script location
    config_snapshot,
    fixture_action,
    fixture_context,
    fixture_context_syntax,
    fixture_renewal,
    fixture_restore,
)

LABEL = "io.opsark.nginx.fixture"
TARGET = "opsark-isolated-restore-fixture.conf"
STATE_DIR = "/run/opsark-nginx-live"
TMPFS = "rw,nosuid,nodev,noexec,mode=0700,uid=65534,gid=65534,size=2m"
NGINX_COMMAND = (
    "/usr/sbin/nginx",
    "-e",
    "stderr",
    "-p",
    STATE_DIR,
    "-c",
    "/fixture-wrapper.conf",
)
CONTEXT_COMMAND = (*NGINX_COMMAND[:-1], "/fixture-runtime/nginx.conf")
WRAPPER = b"""daemon off;
master_process on;
worker_processes 1;
pid /run/opsark-nginx-live/nginx.pid;
error_log stderr crit;
events { worker_connections 16; }
http {
    access_log off;
    client_body_temp_path /run/opsark-nginx-live/body;
    proxy_temp_path /run/opsark-nginx-live/proxy;
    fastcgi_temp_path /run/opsark-nginx-live/fastcgi;
    uwsgi_temp_path /run/opsark-nginx-live/uwsgi;
    scgi_temp_path /run/opsark-nginx-live/scgi;
    server {
        listen 127.0.0.1:18087 default_server;
        server_name _;
        return 404;
    }
    server {
        listen 127.0.0.1:18087;
        server_name control.opsark.invalid;
        location = /healthz { default_type text/plain; return 200 "opsark-control"; }
    }
    include /fixture-sites/opsark-isolated-restore-fixture.conf;
}
"""
_ID = re.compile(r"[0-9a-f]{64}\Z")
_ENV = {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}
_INSPECT_FIELDS = (
    ".Id",
    ".Image",
    ".State.Running",
    ".State.Pid",
    ".State.StartedAt",
    ".Path",
    ".Args",
    ".Config.User",
    '(index .Config.Labels "io.opsark.nginx.fixture")',
    ".HostConfig.NetworkMode",
    '(index .HostConfig "Privileged")',
    ".HostConfig.ReadonlyRootfs",
    '(index .HostConfig "CapAdd")',
    ".HostConfig.CapDrop",
    ".HostConfig.SecurityOpt",
    '(index .HostConfig "PidMode")',
    ".HostConfig.IpcMode",
    '(index .HostConfig "UTSMode")',
    '(index .HostConfig "CgroupnsMode")',
    '(index .HostConfig "Devices")',
    '(index .HostConfig "DeviceRequests")',
    '(index .HostConfig "DeviceCgroupRules")',
    '(index .HostConfig "PortBindings")',
    ".HostConfig.Tmpfs",
    ".Mounts",
    ".NetworkSettings.Networks",
)
_INSPECT = "\n".join("{{json " + field + "}}" for field in _INSPECT_FIELDS)
_PROBE = (
    "wrapper_sha256="
    + repr(hashlib.sha256(WRAPPER).hexdigest())
    + "\nexpected_dependencies="
    + repr(sorted(fixture_context.FIXTURE_FILES))
    + "\n"
    + r"""
import hashlib,http.client,json,os,re,socket,ssl,stat,subprocess,sys
from pathlib import Path

tls=None
def verify_tls_files():
    fields=("dev","ino","size","mtime_ns","ctime_ns","mode","uid","gid")
    entries={".":tls["directory"],**tls["files"]}
    for name,expected in entries.items():
        info=(Path("/fixture-tls")/name).stat(follow_symlinks=False)
        if name=="." and not stat.S_ISDIR(info.st_mode):
            raise ValueError
        if name!="." and (not stat.S_ISREG(info.st_mode) or info.st_nlink!=1):
            raise ValueError
        current={field:(stat.S_IMODE(info.st_mode) if field=="mode" else getattr(info,"st_"+field))
                 for field in fields}
        if current!=expected:
            raise ValueError

def verify_served_chain(tls_socket,host):
    expected=[tls["leaf_sha256"][host],tls["intermediate_sha256"][host]]
    if tls_socket.session_reused:
        raise ValueError
    if hasattr(tls_socket,"get_unverified_chain"):
        chain=tls_socket.get_unverified_chain()
        if not chain or [hashlib.sha256(der).hexdigest() for der in chain]!=expected:
            raise ValueError
        return
    # Python 3.12 has no public wire-chain method. Use another authenticated
    # handshake to the same loopback listener and inspect only its chain section.
    result=subprocess.run(
        ["/usr/bin/openssl","s_client","-connect","127.0.0.1:18087",
         "-servername",host,"-verify_hostname",host,"-verify_return_error",
         "-verifyCAfile","/fixture-tls/root.pem","-no-CAfile","-no-CApath","-no-CAstore",
         "-showcerts","-no_ticket"],
        stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,
        env={"PATH":"/usr/bin:/bin","LC_ALL":"C"},timeout=2,check=False,
    )
    if result.returncode or len(result.stdout)>65536:
        raise ValueError
    lines=result.stdout.splitlines()
    index=lines.index(b"Certificate chain")+1
    end=lines.index(b"---",index)
    section=b"\n".join(lines[index:end])
    pattern=rb"-----BEGIN CERTIFICATE-----\n[A-Za-z0-9+/=\n]+-----END CERTIFICATE-----"
    blocks=re.findall(pattern,section)
    if [hashlib.sha256(ssl.PEM_cert_to_DER_cert(pem.decode("ascii"))).hexdigest()
        for pem in blocks]!=expected:
        raise ValueError

def fetch(host):
    connection=http.client.HTTPConnection("127.0.0.1", 18087, timeout=1)
    try:
        if tls is not None:
            raw=socket.create_connection(("127.0.0.1",18087),timeout=1)
            try:
                connection.sock=tls_context.wrap_socket(raw,server_hostname=host)
            except BaseException:
                raw.close()
                raise
            leaf=connection.sock.getpeercert(binary_form=True)
            leaf_pin=tls["leaf_sha256"][host] if "leaf_sha256" in tls else tls["cert_sha256"]
            if not leaf or hashlib.sha256(leaf).hexdigest()!=leaf_pin:
                raise ValueError
            if "leaf_sha256" in tls:
                verify_served_chain(connection.sock,host)
        connection.request("GET", "/healthz", headers={"Host":host})
        response=connection.getresponse()
        return response.status,response.read(512)
    finally:
        connection.close()
try:
    if len(sys.argv) not in (4,5,6) or {name for _,name in socket.if_nameindex()}!={"lo"}:
        sys.exit(1)
    if len(sys.argv) in (5,6):
        records=json.loads(sys.argv[4])
        if sorted(row[0] for row in records)!=expected_dependencies:
            sys.exit(1)
        for relative,sha,device,inode in records:
            with (Path("/fixture-runtime")/relative).open("rb") as source:
                body=source.read(4097)
                info=os.fstat(source.fileno())
            if (
                len(body)>4096 or hashlib.sha256(body).hexdigest()!=sha
                or (info.st_dev,info.st_ino)!=(device,inode)
            ):
                sys.exit(1)
    elif hashlib.sha256(Path("/fixture-wrapper.conf").read_bytes()).hexdigest()!=wrapper_sha256:
        sys.exit(1)
    expected_sha,dev,ino=sys.argv[1:4]
    with Path("/fixture-sites/opsark-isolated-restore-fixture.conf").open("rb") as source:
        content=source.read(1025)
        info=os.fstat(source.fileno())
    if (
        len(content)>1024 or hashlib.sha256(content).hexdigest()!=expected_sha
        or (info.st_dev,info.st_ino)!=(int(dev),int(ino))
    ):
        sys.exit(1)
    if len(sys.argv)==6:
        tls=json.loads(sys.argv[5])
        if "leaf_sha256" in tls:
            names={"root.pem",*[role+ending for role in ("target","control","default")
                               for ending in ("-chain.pem","-key.pem")]}
            hosts={"target.opsark.invalid","control.opsark.invalid","unknown.opsark.invalid"}
            if (
                set(tls["files"])!=names or set(tls["leaf_sha256"])!=hosts
                or set(tls["intermediate_sha256"])!=hosts
            ):
                raise ValueError
            ca_file="/fixture-tls/root.pem"
        else:
            if set(tls["files"])!={"cert.pem","key.pem"}:
                raise ValueError
            ca_file="/fixture-tls/cert.pem"
        verify_tls_files()
        if "leaf_sha256" in tls:
            with Path(ca_file).open("rb") as root:
                if hashlib.sha256(root.read(16385)).hexdigest()!=tls["root_pem_sha256"]:
                    raise ValueError
        tls_context=ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        tls_context.minimum_version=ssl.TLSVersion.TLSv1_2
        tls_context.load_verify_locations(cafile=ca_file)
    target=fetch("target.opsark.invalid")
    sibling=fetch("control.opsark.invalid")
    missing=fetch("unknown.opsark.invalid")
    if target[0]!=200 or sibling!=(200,b"opsark-control") or missing[0]!=404:
        sys.exit(1)
    if tls is not None:
        verify_tls_files()
    if target[1]==b"opsark-original":
        print("original")
    elif target[1]==b"opsark-candidate":
        print("candidate")
    else:
        sys.exit(1)
except (
    OSError,TypeError,ValueError,KeyError,http.client.HTTPException,subprocess.SubprocessError
):
    sys.exit(1)
"""
)


class RuntimeRefused(ValueError):
    """The exact isolated runtime could not be verified."""


class FixtureRuntime:
    def __init__(self, workspace: Path, container: str, image: str, docker_config: str):
        if not _ID.fullmatch(container) or not re.fullmatch(r"sha256:[0-9a-f]{64}", image):
            raise RuntimeRefused("An exact container and image ID are required")
        if not fixture_action.WORKSPACE_NAME.fullmatch(workspace.name):
            raise RuntimeRefused("The isolated workspace identifier is invalid")
        self.policy = fixture_action.fixture_policy(workspace)
        self.rich = fixture_context.has_context(self.policy)
        self.workspace = workspace
        self.container = container
        self.image = image
        self.base = [
            "/usr/bin/docker",
            "--host",
            "unix:///var/run/docker.sock",
            "--config",
            docker_config,
        ]
        self.identity: tuple[int, str] | None = None
        self.pidfd: int | None = None

    def close(self) -> None:
        self.identity = None
        if self.pidfd is not None:
            descriptor, self.pidfd = self.pidfd, None
            self._close_pidfd(descriptor)

    def _close_pidfd(self, descriptor: int) -> None:
        os.close(descriptor)

    def _pin(self, pid: int) -> int:
        if not hasattr(os, "pidfd_open") or not hasattr(signal, "pidfd_send_signal"):
            raise RuntimeRefused("The local kernel cannot pin the fixture master")
        status = Path("/proc") / str(pid) / "stat"

        def start_tick() -> bytes:
            fields = status.read_bytes().rsplit(b") ", 1)[-1].split()
            if len(fields) <= 19 or not fields[19].isdigit():
                raise RuntimeRefused("The fixture process identity is unavailable")
            return fields[19]

        before = start_tick()
        descriptor = os.pidfd_open(pid)
        try:
            if start_tick() != before:
                raise RuntimeRefused("The fixture process changed while pinning it")
            signal.pidfd_send_signal(descriptor, 0)
        except BaseException:
            self._close_pidfd(descriptor)
            raise
        return descriptor

    def _send_hup(self, descriptor: int) -> None:
        signal.pidfd_send_signal(descriptor, signal.SIGHUP)

    def _docker(self, *args: str, limit: int = 8192) -> bytes:
        result = subprocess.run(  # noqa: S603 -- fixed commands scoped to an exact fixture container.
            [*self.base, *args],
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            env=_ENV,
            timeout=5,
            check=False,
        )
        if result.returncode != 0 or len(result.stdout) > limit:
            raise RuntimeRefused("Isolated runtime command unavailable")
        return result.stdout

    def _identity(self) -> tuple[int, str]:
        wrapper = self.workspace / "runtime" / "nginx.conf"
        context = self._context()
        if context is None:
            with config_snapshot._directory(wrapper.parent, self.policy) as parent:
                data, _ = config_snapshot._read(parent, wrapper.name, len(WRAPPER), self.policy)
            if data != WRAPPER:
                raise RuntimeRefused("The fixture wrapper does not match the supported runtime")
        command = CONTEXT_COMMAND if context is not None else NGINX_COMMAND
        tls = (context.tls or context.tls_chain) if context is not None else None
        lines = self._docker(
            "container", "inspect", "--format", _INSPECT, self.container
        ).splitlines()
        if len(lines) != len(_INSPECT_FIELDS):
            raise RuntimeRefused("The runtime metadata is incomplete")
        (
            identity,
            image,
            running,
            pid,
            started,
            executable,
            args,
            user,
            label,
            network,
            privileged,
            read_only,
            cap_add,
            cap_drop,
            security,
            pid_mode,
            ipc_mode,
            uts_mode,
            cgroupns_mode,
            devices,
            device_requests,
            device_rules,
            ports,
            tmpfs,
            mounts,
            networks,
        ) = [json.loads(line) for line in lines]
        if (
            identity != self.container
            or image != self.image
            or running is not True
            or type(pid) is not int
            or pid <= 0
            or not isinstance(started, str)
            or not started
            or executable != command[0]
            or args != list(command[1:])
            or user != "65534:65534"
            or label != self.workspace.name
            or network != "none"
            or privileged not in (False, None)
            or read_only is not True
            or cap_add not in (None, [])
            or cap_drop != ["ALL"]
            or security != ["no-new-privileges:true"]
            or pid_mode not in (None, "")
            or ipc_mode != "none"
            or uts_mode not in (None, "")
            or cgroupns_mode != "private"
            or any(value not in (None, []) for value in (devices, device_requests, device_rules))
            or ports not in (None, {})
            or tmpfs != {STATE_DIR: TMPFS}
            or not isinstance(mounts, list)
            or len(mounts) != (3 if tls is not None else 2)
            or not isinstance(networks, dict)
            or set(networks) != {"none"}
        ):
            raise RuntimeRefused("The container is outside the isolated Nginx fixture scope")
        expected = {
            "/fixture-sites": str(self.policy.config_directory),
            **(
                {"/fixture-runtime": str(wrapper.parent)}
                if context is not None
                else {"/fixture-wrapper.conf": str(wrapper)}
            ),
        }
        if tls is not None:
            expected["/fixture-tls"] = str(self.workspace / "tls")
        observed = {}
        for mount in mounts:
            if (
                not isinstance(mount, dict)
                or mount.get("Type") != "bind"
                or mount.get("RW") is not False
                or mount.get("Propagation") != "rprivate"
                or not isinstance(mount.get("Destination"), str)
            ):
                raise RuntimeRefused("The fixture mount is unsafe")
            observed[mount["Destination"]] = mount.get("Source")
        if observed != expected:
            raise RuntimeRefused("The fixture mounts do not match this workspace")
        return pid, started

    def _context(self) -> fixture_context.RuntimeContext | None:
        if fixture_context.has_context(self.policy) != self.rich:
            raise RuntimeRefused("The fixture context profile changed")
        return fixture_context.verify_context(self.policy) if self.rich else None

    def _context_digest(self) -> str:
        context = self._context()
        if context is None:
            raise RuntimeRefused("A sealed fixture context is required")
        return context.fingerprint

    def context_reader(self):
        return self._context_digest if self.rich else None

    def _site(self) -> tuple[str, dict[str, int]]:
        with config_snapshot._directory(self.policy.config_directory, self.policy) as directory:
            data, identity = config_snapshot._read(directory, TARGET, 1024, self.policy)
        return hashlib.sha256(data).hexdigest(), identity

    def _probe(self, expected: bytes) -> bool:
        digest, site = self._site()
        context = self._context()
        dependencies = (
            [
                json.dumps(
                    [
                        [name, info["sha256"], info["dev"], info["ino"]]
                        for name, info in sorted(context.files.items())
                    ],
                    separators=(",", ":"),
                )
            ]
            if context is not None
            else []
        )
        if context is not None and context.tls is not None:
            tls = context.tls
            dependencies.append(
                json.dumps(
                    {
                        "cert_sha256": tls.cert_sha256,
                        "directory": tls.directory,
                        "files": {"cert.pem": tls.certificate, "key.pem": tls.key},
                    },
                    separators=(",", ":"),
                )
            )
        elif context is not None and context.tls_chain is not None:
            chain = context.tls_chain
            dependencies.append(
                json.dumps(
                    {
                        "leaf_sha256": chain.leaf_sha256,
                        "intermediate_sha256": chain.intermediate_sha256,
                        "root_pem_sha256": chain.root_pem_sha256,
                        "directory": chain.directory,
                        "files": chain.files,
                    },
                    separators=(",", ":"),
                )
            )
        observed = self._docker(
            "exec",
            self.container,
            "/usr/bin/python3",
            "-I",
            "-B",
            "-c",
            _PROBE,
            digest,
            str(site["dev"]),
            str(site["ino"]),
            *dependencies,
            limit=32,
        )
        return (
            observed == expected + b"\n"
            and self._site() == (digest, site)
            and self._context() == context
        )

    def fingerprint(self) -> str:
        identity = self._identity()
        if self.identity is not None and identity != self.identity:
            raise RuntimeRefused("The original fixture process could not be verified")
        context = self._context()
        return hashlib.sha256(
            config_snapshot._json(
                {
                    "container": self.container,
                    "image": self.image,
                    "pid": identity[0],
                    "started": identity[1],
                    "fixture_machine_sha256": config_snapshot._machine(self.policy),
                    **(
                        {"context_sha256": context.fingerprint}
                        if context is not None
                        else {"wrapper_sha256": hashlib.sha256(WRAPPER).hexdigest()}
                    ),
                }
            )
        ).hexdigest()

    def preflight(self, expected: bytes = b"original") -> bool:
        self.close()
        identity = self._identity()
        descriptor = self._pin(identity[0])
        try:
            ready = self._probe(expected) and self._identity() == identity
        except BaseException:
            self._close_pidfd(descriptor)
            raise
        if not ready:
            self._close_pidfd(descriptor)
            return False
        self.identity = identity
        self.pidfd = descriptor
        return True

    def approval_preflight(self, approval: Path) -> bool:
        proof = config_snapshot.inspect_approval(
            approval, policy=self.policy, context_reader=self.context_reader()
        )
        return (
            proof["approval_status"] == "approved"
            and proof["image_sha256"] == self.image
            and self.preflight()
        )

    def reload_and_verify(self, expected: bytes = b"candidate") -> bool:
        if self.identity is None or self.pidfd is None or self._identity() != self.identity:
            return False
        if self.rich:
            previous = b"original" if expected == b"candidate" else b"candidate"
            if not self._probe(previous) or self._identity() != self.identity:
                return False
        # A container ID can survive restart; a pidfd can signal only the pinned master.
        try:
            self._send_hup(self.pidfd)
        except OSError:
            return False
        for _ in range(8):
            if self._identity() != self.identity:
                return False
            try:
                if self._probe(expected):
                    return self._identity() == self.identity
            except RuntimeRefused:
                pass
            time.sleep(0.25)
        return False


def main() -> int:
    parser = config_snapshot._Parser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    apply = commands.add_parser("apply")
    status = commands.add_parser("status")
    lookup = commands.add_parser("action-id")
    reconcile = commands.add_parser("reconcile")
    approve_restore = commands.add_parser("approve-restore")
    restore = commands.add_parser("restore")
    restore_id = commands.add_parser("restore-id")
    seal = commands.add_parser("seal-context")
    tls_mode = seal.add_mutually_exclusive_group()
    tls_mode.add_argument("--tls", action="store_true")
    tls_mode.add_argument("--tls-chain", action="store_true")
    prepare = commands.add_parser("prepare-context")
    validate = commands.add_parser("validate-context")
    approve = commands.add_parser("approve-context")
    renewal_candidate = commands.add_parser("renewal-candidate")
    prepare_renewal = commands.add_parser("prepare-renewal")
    inspect_renewal = commands.add_parser("inspect-renewal")
    for command in (
        apply,
        status,
        lookup,
        reconcile,
        approve_restore,
        restore,
        restore_id,
        seal,
        prepare,
        validate,
        approve,
        renewal_candidate,
        prepare_renewal,
        inspect_renewal,
    ):
        command.add_argument("--workspace", type=Path, required=True)
    for command in (apply, lookup, approve_restore, restore, restore_id):
        command.add_argument("--approval", type=Path, required=True)
    for command in (apply, reconcile, approve_restore, restore, prepare_renewal):
        command.add_argument("--container", required=True)
        command.add_argument("--image", required=True)
    prepare_renewal.add_argument("--candidate-container", required=True)
    prepare_renewal.add_argument("--expected-context-sha256", required=True)
    for command in (apply, approve_restore, restore):
        command.add_argument("--confirm", action="store_true", required=True)
    for command in (approve_restore, restore):
        command.add_argument("--expected-original-sha256", required=True)
    apply.add_argument("--expected-approval-id", required=True)
    apply.add_argument("--expected-candidate-sha256", required=True)
    for command in (status, reconcile):
        command.add_argument("--action-id", required=True)
    approve_restore.add_argument("--original-action-id", required=True)
    approve_restore.add_argument("--output", type=Path, required=True)
    restore.add_argument("--expected-approval-id", required=True)
    for command in (prepare, approve):
        command.add_argument("--output", type=Path, required=True)
    prepare.add_argument("--snapshot", type=Path, required=True)
    prepare.add_argument("--candidate", type=Path, required=True)
    prepare.add_argument("--expected-sha256", required=True)
    for command in (validate, approve):
        command.add_argument("--plan", type=Path, required=True)
        command.add_argument("--image", required=True)
    approve.add_argument("--expected-plan-id", required=True)
    approve.add_argument("--expected-candidate-sha256", required=True)
    approve.add_argument("--confirm", action="store_true", required=True)
    args = parser.parse_args()
    try:
        if args.command == "status":
            result = fixture_action.inspect_action(args.workspace, args.action_id)
        elif args.command == "renewal-candidate":
            fixture_action.fixture_policy(args.workspace)
            candidate = fixture_renewal.candidate_workspace(args.workspace)
            print(json.dumps({"workspace_name": candidate.name}))
            return 0
        elif args.command == "inspect-renewal":
            result = fixture_renewal.inspect(args.workspace)
            print(json.dumps(result or {"status": "missing"}, sort_keys=True))
            return int(result is None)
        elif args.command in {
            "seal-context",
            "prepare-context",
            "validate-context",
            "approve-context",
        }:
            result = _context_command(args)
            print(json.dumps(result, sort_keys=True))
            return int(
                args.command == "validate-context"
                and (
                    result.get("plan_status") != "ready" or result.get("syntax_status") != "passed"
                )
            )
        elif args.command in {"action-id", "restore-id"}:
            identify = (
                fixture_action.action_id_for_approval
                if args.command == "action-id"
                else fixture_restore.restore_action_id
            )
            print(json.dumps({"action_id": identify(args.workspace, args.approval)}))
            return 0
        else:
            with (
                TemporaryDirectory(prefix="opsark-fixture-docker-", dir="/tmp") as config,
                closing(
                    FixtureRuntime(args.workspace, args.container, args.image, config)
                ) as runtime,
            ):
                if args.command == "prepare-renewal":
                    workspace = fixture_renewal.candidate_workspace(args.workspace)
                    with closing(
                        FixtureRuntime(workspace, args.candidate_container, args.image, config)
                    ) as candidate:
                        result = fixture_renewal.prepare(
                            runtime, candidate, expected_context_sha256=args.expected_context_sha256
                        )
                else:
                    result = _operate(args, runtime)
    except (OSError, TypeError, ValueError, subprocess.SubprocessError):
        print("The isolated fixture action could not be confirmed.", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return int(
        result.get("status") != "verified"
        and result.get("status") != "pending_approval"
        and result.get("reconciliation_status") != "verified"
        and result.get("approval_status") != "approved"
    )


def _operate(args, runtime: FixtureRuntime) -> dict:
    def verify_candidate():
        return runtime.preflight(b"candidate")

    if args.command == "apply":
        return fixture_action.apply_fixture(
            args.workspace,
            args.approval,
            args.expected_approval_id,
            args.expected_candidate_sha256,
            confirm=args.confirm,
            preflight=lambda: runtime.approval_preflight(args.approval),
            runtime_fingerprint=runtime.fingerprint,
            reload_and_verify=runtime.reload_and_verify,
            context_reader=runtime.context_reader(),
        )
    if args.command == "reconcile":
        return fixture_action.reconcile_fixture(
            args.workspace,
            args.action_id,
            runtime_fingerprint=runtime.fingerprint,
            verify_candidate=verify_candidate,
        )
    if args.command == "approve-restore":
        return fixture_restore.approve_restore(
            args.workspace,
            args.original_action_id,
            args.approval,
            args.expected_original_sha256,
            args.output,
            runtime_fingerprint=runtime.fingerprint,
            verify_candidate=verify_candidate,
            confirm=args.confirm,
            context_reader=runtime.context_reader(),
            syntax_check=(lambda data, image: _validate_context(runtime.policy, data, image))
            if runtime.rich
            else None,
        )
    return fixture_restore.restore_fixture(
        args.workspace,
        args.approval,
        args.expected_approval_id,
        args.expected_original_sha256,
        runtime_fingerprint=runtime.fingerprint,
        verify_candidate=verify_candidate,
        reload_and_verify=lambda: runtime.reload_and_verify(b"original"),
        confirm=args.confirm,
        context_reader=runtime.context_reader(),
    )


def _validate_context(policy: config_snapshot.SnapshotPolicy, data: bytes, image: str) -> str:
    context = fixture_context.verify_context(policy)
    if context.tls is not None or context.tls_chain is not None:
        return fixture_context_syntax.validate(data, image, tls_directory=policy.anchor / "tls")
    return fixture_context_syntax.validate(data, image)


def _context_command(args) -> dict:
    policy = fixture_action.fixture_policy(args.workspace)
    if args.command == "seal-context":
        context = fixture_context.seal_context(policy, tls=args.tls, tls_chain=args.tls_chain)
        return {
            "schema_version": 1,
            "context_sha256": context.fingerprint,
            "dependency_count": len(context.files),
            **(
                {"tls": True, "certificate_sha256": context.tls.cert_sha256}
                if context.tls is not None
                else {}
            ),
            **(
                {"tls_chain": True, "leaf_sha256": context.tls_chain.leaf_sha256}
                if context.tls_chain is not None
                else {}
            ),
        }

    def read_context() -> str:
        return fixture_context.verify_context(policy).fingerprint

    if args.command == "prepare-context":
        return config_snapshot.prepare(
            args.snapshot,
            args.candidate,
            args.expected_sha256,
            args.output,
            policy=policy,
            context_reader=read_context,
        )
    if args.command == "validate-context":
        return config_snapshot.validate_plan(
            args.plan,
            args.image,
            policy=policy,
            context_reader=read_context,
            syntax_check=lambda data, image: _validate_context(policy, data, image),
        )
    return config_snapshot.approve_plan(
        args.plan,
        args.image,
        args.expected_plan_id,
        args.expected_candidate_sha256,
        args.output,
        confirm=args.confirm,
        policy=policy,
        context_reader=read_context,
        syntax_check=lambda data, image: _validate_context(policy, data, image),
    )


if __name__ == "__main__":
    raise SystemExit(main())
