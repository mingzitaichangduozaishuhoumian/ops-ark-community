"""Bounded acceptance-only loopback transport into one owned management container.

The caller owns and authenticates the outer SSH transport.  This module never
loads credentials, changes production SSH clients, reconnects, or publishes a
remote host port.  The inner SSH client's normal pin and role checks still run.

Budgets are separate: a local accepted connection lasts at most 30 seconds;
the remote inspector has an 8-second alarm, the inner proxy a 30-second alarm
and 28-second forwarding loop, and the outer wrapper a 36-second timeout plus
one second to kill.  A stopped local connection can therefore leave its owned
remote process for up to about seven further seconds, bounded by those limits
and the fixture's independent 600-second container lifetime.
"""

import inspect
import re
import shlex
import socket
import threading
import time
from contextlib import suppress
from dataclasses import asdict, dataclass
from pathlib import PurePosixPath
from typing import Protocol

ADDRESS = ("127.0.0.1", 22423)
MAX_CONCURRENT = 4
MAX_CONNECTIONS = 32
CONNECTION_SECONDS = 30
LIFETIME_SECONDS = 600
MAX_BYTES_PER_DIRECTION = 262144
BUFFER_BYTES = 65536
LABEL = "io.opsark.ssh-defense-requests"


class RelayRefused(RuntimeError):
    def __init__(self):
        super().__init__("The fixed isolated SSH relay could not be confirmed.")


@dataclass(frozen=True)
class RelayScope:
    stage_root: str
    workspace: str
    container_id: str
    network_id: str
    image_id: str
    fixture_id: str

    def __post_init__(self):
        if any(type(value) is not str for value in asdict(self).values()):
            raise RelayRefused()
        stage, workspace = PurePosixPath(self.stage_root), PurePosixPath(self.workspace)
        if (
            not re.fullmatch(r"/var/lib/opsark-release-lab/[0-9a-f]{14}", self.stage_root)
            or str(stage) != self.stage_root
            or str(workspace) != self.workspace
            or workspace.parent != stage
            or not re.fullmatch(r"[A-Za-z0-9_-]{1,80}", workspace.name)
            or re.fullmatch(r"[0-9a-f]{64}", self.container_id) is None
            or re.fullmatch(r"[0-9a-f]{64}", self.network_id) is None
            or re.fullmatch(r"sha256:[0-9a-f]{64}", self.image_id) is None
            or re.fullmatch(r"[0-9a-f]{16}", self.fixture_id) is None
        ):
            raise RelayRefused()


def _require(condition):
    if not condition:
        raise ValueError("Fixed isolated transport refused")


def _verify_inspections(spec, image, container, network):
    """This exact pure validator is included in the fixed remote inspector."""
    label = "io.opsark.ssh-defense-requests"
    name = "opsark-requests-" + spec["fixture_id"]
    config, host = container["Config"], container["HostConfig"]
    _require(image["Id"] == spec["image_id"] and not image["Config"].get("Volumes"))
    _require(
        container["Id"] == spec["container_id"]
        and container["Image"] == spec["image_id"]
        and container["Name"] == "/" + name + "-management"
        and container["State"]["Running"] is True
        and container["State"].get("Paused", False) is False
        and config["Labels"] == {**(image["Config"].get("Labels") or {}), label: spec["fixture_id"]}
        and config["User"] == "0:0"
        and config["Entrypoint"] == ["/usr/bin/timeout"]
        and config["Cmd"] == ["-k", "2s", "600s", "/bin/sleep", "infinity"]
        and not config.get("Volumes")
    )
    _require(
        host["Privileged"] is False
        and host["CapDrop"] in (["ALL"], ["CAP_ALL"])
        and host["CapAdd"] in (None, [])
        and host["ReadonlyRootfs"] is True
        and host["SecurityOpt"] == ["no-new-privileges:true"]
        and host["NetworkMode"] == name
        and not host["PidMode"]
        and host["IpcMode"] == "private"
        and host["CgroupnsMode"] == "private"
        and not host["UTSMode"]
        and not host["UsernsMode"]
        and not host["Devices"]
        and not host.get("DeviceRequests")
        and not host["PortBindings"]
        and not host["PublishAllPorts"]
        and not host["VolumesFrom"]
        and host["PidsLimit"] == 96
        and host["Memory"] == 192 * 1024**2
        and host["MemorySwap"] == host["Memory"]
        and host["NanoCpus"] == 500_000_000
        and len(host["Ulimits"]) == 2
        and {(item["Name"], item["Soft"], item["Hard"]) for item in host["Ulimits"]}
        == {("core", 0, 0), ("nofile", 256, 256)}
        and host["LogConfig"]["Type"] == "none"
        and host["RestartPolicy"]["Name"] == "no"
    )
    mounts = {
        (row["Source"], row["Destination"], row["RW"], row["Type"], row["Propagation"])
        for row in container["Mounts"]
    }
    _require(
        len(container["Mounts"]) == 2
        and mounts
        == {
            (spec["workspace"] + "/code", "/fixture-code", False, "bind", "rprivate"),
            (spec["workspace"] + "/management", "/fixture-client", False, "bind", "rprivate"),
        }
    )
    attached = container["NetworkSettings"]["Networks"]
    _require(
        set(attached) == {name}
        and attached[name]["NetworkID"] == spec["network_id"]
        and attached[name]["IPAddress"] == "198.18.241.4"
        and attached[name]["IPPrefixLen"] == 28
        and not attached[name].get("GlobalIPv6Address")
    )
    ipam = network["IPAM"]["Config"]
    _require(
        network["Id"] == spec["network_id"]
        and network["Name"] == name
        and network["Driver"] == "bridge"
        and network["Internal"] is True
        and network["EnableIPv6"] is False
        and not network.get("Ingress")
        and not network.get("Attachable")
        and not network.get("Options")
        and network["Labels"] == {label: spec["fixture_id"]}
        and type(ipam) is list
        and len(ipam) == 1
        and type(ipam[0]) is dict
        and set(ipam[0]) in ({"Subnet", "Gateway"}, {"Subnet", "Gateway", "IPRange"})
        and ipam[0]["Subnet"] == "198.18.241.0/28"
        and ipam[0]["Gateway"] == "198.18.241.1"
        and ("IPRange" not in ipam[0] or ipam[0]["IPRange"] == "")
    )
    endpoints = network["Containers"]
    _require(
        type(endpoints) is dict
        and len(endpoints) == 4
        and spec["container_id"] in endpoints
        and endpoints[spec["container_id"]]["Name"] == name + "-management"
        and {
            (row["Name"], row["IPv4Address"], row.get("IPv6Address", ""))
            for row in endpoints.values()
        }
        == {
            (name + "-" + role, address + "/28", "")
            for role, address in (
                ("target", "198.18.241.2"),
                ("candidate", "198.18.241.3"),
                ("management", "198.18.241.4"),
                ("alternate", "198.18.241.5"),
            )
        }
    )


# This program is fixed. No address, port, argv, filesystem path or payload is
# interpolated into it. Its stdout is exclusively the nested SSH byte stream.
PROXY_SOURCE = r"""
import os, signal, socket, select, sys, time
from pathlib import Path
def refuse(): raise ValueError('Fixed isolated transport refused')
def alarm(_signum, _frame): raise TimeoutError()
try:
 signal.signal(signal.SIGALRM, alarm); signal.alarm(30)
 status = dict(line.split(':',1)
  for line in Path('/proc/self/status').read_text().splitlines() if ':' in line)
 if (not Path('/.dockerenv').is_file() or os.geteuid()!=0
  or int(status['CapEff'].strip(),16)!=0 or status['NoNewPrivs'].strip()!='1'): refuse()
 stream=socket.socket(socket.AF_INET,socket.SOCK_STREAM); stream.settimeout(3)
 stream.bind(('198.18.241.4',0)); stream.connect(('198.18.241.2',22423))
 if (stream.getsockname()[0]!='198.18.241.4'
  or stream.getpeername()!=('198.18.241.2',22423)): refuse()
 stream.setblocking(False); os.set_blocking(0,False); os.set_blocking(1,False)
 incoming=bytearray(); outgoing=bytearray(); read_stdin=read_socket=True
 shut_socket=shut_stdout=False; totals=[0,0]; deadline=time.monotonic()+28
 while time.monotonic()<deadline:
  reads=([0] if read_stdin and len(incoming)<65536 else [])
  reads+=([stream] if read_socket and len(outgoing)<65536 else [])
  writes=([stream] if incoming else [])+([1] if outgoing else [])
  readable,writable,_=select.select(reads,writes,[],0.05)
  if 0 in readable:
   value=os.read(0,min(4096,65536-len(incoming)))
   if value: totals[0]+=len(value); incoming.extend(value)
   else: read_stdin=False
  if stream in readable:
   value=stream.recv(min(4096,65536-len(outgoing)))
   if value: totals[1]+=len(value); outgoing.extend(value)
   else: read_socket=False
  if max(totals)>262144: refuse()
  if stream in writable and incoming: del incoming[:stream.send(incoming[:4096])]
  if 1 in writable and outgoing: del outgoing[:os.write(1,outgoing[:4096])]
  if not read_stdin and not incoming and not shut_socket:
   stream.shutdown(socket.SHUT_WR); shut_socket=True
  if not read_socket and not outgoing and not shut_stdout:
   os.close(1); shut_stdout=True
  if not read_stdin and not read_socket and not incoming and not outgoing: break
 else: refuse()
 stream.close()
except Exception:
 sys.exit(111)
"""


INSPECTOR_SOURCE = r"""
import json, os, signal, stat, subprocess, sys
from pathlib import Path
def alarm(_signum, _frame): raise TimeoutError()
def directory(path, private=False):
 _require(path.is_absolute() and path.resolve(strict=True)==path)
 for part in (path,*path.parents):
  value=part.lstat()
  _require(stat.S_ISDIR(value.st_mode) and value.st_uid==0 and not value.st_mode&0o022)
 _require(not private or stat.S_IMODE(path.stat().st_mode)==0o700)
def inspect_one(kind, identity):
 args=['/usr/bin/docker','--host','unix:///var/run/docker.sock','--config',S['workspace'],kind,'inspect',identity]
 process=subprocess.Popen(args,stdin=subprocess.DEVNULL,stdout=subprocess.PIPE,stderr=subprocess.DEVNULL,env={'PATH':'/usr/sbin:/usr/bin:/sbin:/bin','LC_ALL':'C'})
 try:
  raw=process.stdout.read(262145)
  _require(0<len(raw)<=262144 and process.wait(timeout=3)==0)
  value=json.loads(raw)
  _require(type(value) is list and len(value)==1)
  return value[0]
 finally:
  if process.poll() is None: process.kill(); process.wait(timeout=1)
  process.stdout.close()
try:
 signal.signal(signal.SIGALRM,alarm); signal.alarm(8)
 _require(sys.platform=='linux' and os.geteuid()==0 and not Path('/.dockerenv').exists())
 directory(Path(S['stage_root']),True); directory(Path(S['workspace']),True)
 directory(Path(S['workspace'])/'code',True); directory(Path(S['workspace'])/'management',True)
 image=inspect_one('image',S['image_id'])
 container=inspect_one('container',S['container_id'])
 network=inspect_one('network',S['network_id'])
 _verify_inspections(S,image,container,network)
 signal.alarm(0)
 args=['/usr/bin/timeout','-k','1s','34s','/usr/bin/docker','--host','unix:///var/run/docker.sock','--config',S['workspace'],'exec','-i',S['container_id'],'/usr/bin/python3','-I','-u','-c',PROXY]
 os.execv(args[0],args)
except Exception:
 sys.exit(111)
"""


def remote_command(scope: RelayScope) -> str:
    if type(scope) is not RelayScope:
        raise RelayRefused()
    # Reconstruct to reject objects mutated through low-level Python mechanisms.
    scope = RelayScope(**asdict(scope))
    source = (
        "S="
        + repr(asdict(scope))
        + "\nPROXY="
        + repr(PROXY_SOURCE)
        + "\n"
        + inspect.getsource(_require)
        + "\n"
        + inspect.getsource(_verify_inspections)
        + "\n"
        + INSPECTOR_SOURCE
    )
    return shlex.join(
        ("/usr/bin/timeout", "-k", "1s", "36s", "/usr/bin/python3", "-I", "-u", "-c", source)
    )


class RelayChannel(Protocol):
    closed: bool
    eof_received: bool

    def settimeout(self, timeout: float) -> None: ...
    def exec_command(self, command: str) -> None: ...
    def send_ready(self) -> bool: ...
    def send(self, data: bytes) -> int: ...
    def recv_ready(self) -> bool: ...
    def recv(self, size: int) -> bytes: ...
    def recv_stderr_ready(self) -> bool: ...
    def exit_status_ready(self) -> bool: ...
    def shutdown_write(self) -> None: ...
    def close(self) -> None: ...


@dataclass
class _Connection:
    stream: socket.socket
    deadline: float
    channel: RelayChannel | None = None
    thread: threading.Thread | None = None


class FixedDefenseRelay:
    def __init__(self, scope: RelayScope, open_channel):
        self.command = remote_command(scope)
        if not callable(open_channel):
            raise RelayRefused()
        self.open_channel = open_channel
        self.scope = scope
        self._lock = threading.Lock()
        self._stopped = threading.Event()
        self._connections: dict[int, _Connection] = {}
        self._threads: list[threading.Thread] = []
        self._listener: socket.socket | None = None
        self._acceptor: threading.Thread | None = None
        self._deadline = 0.0
        self._started = False
        self._counts = {
            "accepted": 0,
            "refused": 0,
            "finished": 0,
            "failed": 0,
            "bytes_to_target": 0,
            "bytes_to_client": 0,
        }

    @property
    def statistics(self):
        with self._lock:
            return dict(self._counts, active=len(self._connections), stopped=self._stopped.is_set())

    def __enter__(self):
        if self._started:
            raise RelayRefused()
        self._started = True
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            listener.bind(ADDRESS)
            listener.listen(MAX_CONCURRENT)
            listener.settimeout(0.1)
        except OSError:
            listener.close()
            self._stopped.set()
            raise RelayRefused() from None
        self._listener, self._deadline = listener, time.monotonic() + LIFETIME_SECONDS
        self._acceptor = threading.Thread(
            target=self._accept, name="opsark-fixed-relay", daemon=True
        )
        try:
            self._acceptor.start()
        except RuntimeError:
            listener.close()
            self._listener = self._acceptor = None
            self._stopped.set()
            raise RelayRefused() from None
        return self

    def __exit__(self, _kind, _value, _traceback):
        self.close()

    @staticmethod
    def _close_connection(connection):
        if connection.channel is not None:
            with suppress(Exception):
                connection.channel.close()
        with suppress(OSError):
            connection.stream.shutdown(socket.SHUT_RDWR)
        connection.stream.close()

    def _expire(self):
        with self._lock:
            stale = [
                value for value in self._connections.values() if time.monotonic() >= value.deadline
            ]
        for connection in stale:
            self._close_connection(connection)

    def _admit(self, stream, peer):
        with self._lock:
            if (
                peer[0] != "127.0.0.1"
                or self._stopped.is_set()
                or time.monotonic() >= self._deadline
                or len(self._connections) >= MAX_CONCURRENT
                or self._counts["accepted"] >= MAX_CONNECTIONS
            ):
                self._counts["refused"] += 1
                stream.close()
                return None
            connection = _Connection(
                stream, min(time.monotonic() + CONNECTION_SECONDS, self._deadline)
            )
            self._connections[id(connection)] = connection
            self._counts["accepted"] += 1
        return connection

    def _accept(self):
        listener = self._listener
        if listener is None:
            self._stopped.set()
            return
        try:
            while not self._stopped.is_set() and time.monotonic() < self._deadline:
                self._expire()
                try:
                    stream, peer = listener.accept()
                except TimeoutError:
                    continue
                except OSError:
                    break
                connection = self._admit(stream, peer)
                if connection is not None:
                    worker = threading.Thread(
                        target=self._serve,
                        args=(connection,),
                        name="opsark-fixed-stream",
                        daemon=True,
                    )
                    connection.thread = worker
                    self._threads.append(worker)
                    try:
                        worker.start()
                    except RuntimeError:
                        self._threads.remove(worker)
                        self._close_connection(connection)
                        with self._lock:
                            self._connections.pop(id(connection), None)
                            self._counts["failed"] += 1
                        break
        finally:
            self._stopped.set()
            if self._listener is not None:
                self._listener.close()
            with self._lock:
                remaining = list(self._connections.values())
            for connection in remaining:
                self._close_connection(connection)

    def _serve(self, connection):
        failed = True
        try:
            remaining = connection.deadline - time.monotonic()
            if remaining <= 0 or self._stopped.is_set():
                return
            channel = self.open_channel(timeout=min(5.0, remaining))
            with self._lock:
                connection.channel = channel
            if self._stopped.is_set() or time.monotonic() >= connection.deadline:
                return
            channel.settimeout(0.05)
            channel.exec_command(self.command)
            self._pump(connection)
            failed = False
        except Exception:
            # Deliberately retain no exception text, stderr, address, payload or key.
            failed = True
        finally:
            self._close_connection(connection)
            with self._lock:
                self._connections.pop(id(connection), None)
                self._counts["failed" if failed else "finished"] += 1

    def _pump(self, connection):
        stream, channel = connection.stream, connection.channel
        stream.setblocking(False)
        to_target, to_client = bytearray(), bytearray()
        client_eof = target_eof = sent_eof = returned_eof = False
        totals = [0, 0]
        while not self._stopped.is_set() and time.monotonic() < connection.deadline:
            if not client_eof and len(to_target) < BUFFER_BYTES:
                try:
                    raw = stream.recv(min(4096, BUFFER_BYTES - len(to_target)))
                    if raw:
                        totals[0] += len(raw)
                        to_target.extend(raw)
                    else:
                        client_eof = True
                except BlockingIOError:
                    pass
            if channel.recv_stderr_ready():
                raise RelayRefused()
            if not target_eof and len(to_client) < BUFFER_BYTES and channel.recv_ready():
                raw = channel.recv(min(4096, BUFFER_BYTES - len(to_client)))
                if raw:
                    totals[1] += len(raw)
                    to_client.extend(raw)
                else:
                    target_eof = True
            if not channel.recv_ready() and (
                channel.eof_received or channel.closed or channel.exit_status_ready()
            ):
                target_eof = True
            if max(totals) > MAX_BYTES_PER_DIRECTION:
                raise RelayRefused()
            if to_target and channel.send_ready():
                sent = channel.send(bytes(to_target[:4096]))
                if not 0 < sent <= min(4096, len(to_target)):
                    raise RelayRefused()
                del to_target[:sent]
                with self._lock:
                    self._counts["bytes_to_target"] += sent
            if to_client:
                try:
                    sent = stream.send(to_client[:4096])
                    if sent <= 0:
                        raise RelayRefused()
                    del to_client[:sent]
                    with self._lock:
                        self._counts["bytes_to_client"] += sent
                except BlockingIOError:
                    pass
            if client_eof and not to_target and not sent_eof:
                channel.shutdown_write()
                sent_eof = True
            if target_eof and not to_client and not returned_eof:
                stream.shutdown(socket.SHUT_WR)
                returned_eof = True
            if client_eof and target_eof and not to_target and not to_client:
                return
            self._stopped.wait(0.005)
        raise RelayRefused()

    def close(self):
        self._stopped.set()
        if self._listener is not None:
            self._listener.close()
        with self._lock:
            connections = list(self._connections.values())
        for connection in connections:
            self._close_connection(connection)
        deadline = time.monotonic() + 6
        if self._acceptor is not None and self._acceptor is not threading.current_thread():
            self._acceptor.join(timeout=max(0.0, deadline - time.monotonic()))
        for worker in self._threads:
            worker.join(timeout=max(0.0, deadline - time.monotonic()))
        if (self._acceptor is not None and self._acceptor.is_alive()) or any(
            worker.is_alive() for worker in self._threads
        ):
            raise RelayRefused()


__all__ = ["FixedDefenseRelay", "RelayRefused", "RelayScope"]
