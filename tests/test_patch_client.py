import hashlib
import json
import threading
from types import SimpleNamespace

import paramiko
import pytest

from opsark import patch_client
from opsark.config import HostConfig
from opsark.models import HostPublic
from opsark.patch_client import PatchClientError, PatchTarget, UnknownPatchResult, invoke

POLICY = "a" * 64
JOB = "b" * 32
PLAN = "c" * 32


@pytest.fixture(scope="module")
def server_key():
    return paramiko.RSAKey.generate(2048)


@pytest.fixture
def target(tmp_path, server_key):
    known = tmp_path / "known-hosts"
    known.write_text(f"192.0.2.20 {server_key.get_name()} {server_key.get_base64()}\n")
    readonly = tmp_path / "readonly-key"
    repair = tmp_path / "repair-key"
    readonly.write_text("synthetic-readonly-private-key")
    repair.write_text("synthetic-repair-private-key")
    host = HostConfig(
        public=HostPublic(
            id="server-a",
            name="synthetic",
            address="192.0.2.20",
            source="ssh",
            trusted_hosts_digest=hashlib.sha256(known.read_bytes()).hexdigest(),
        ),
        key_file=readonly,
        known_hosts_file=known,
    )
    return PatchTarget(host=host, key_file=repair, policy_digest=POLICY)


def request(op="scan", **fields):
    value = {"schema_version": 1, "op": op, "policy_digest": POLICY}
    if op == "submit":
        value.update(job_id=JOB, plan_id=PLAN, plan_digest="d" * 64, mode_revision=2)
    return value | fields


class Channel:
    def __init__(self, output=b'{"status":"complete"}', errors=b"", *, code=0):
        self.output = bytearray(output)
        self.errors = bytearray(errors)
        self.code = code
        self.sent = []
        self.closed = False
        self.eof = False
        self.eof_received = True
        self.fail_send = False
        self.never_finish = False
        self.timeout = None

    def settimeout(self, timeout):
        self.timeout = timeout

    def sendall(self, body):
        self.sent.append(body)
        if self.fail_send:
            raise OSError("private transport error must not be exposed")

    def shutdown_write(self):
        self.eof = True

    def recv_ready(self):
        return bool(self.output)

    def recv_stderr_ready(self):
        return bool(self.errors)

    def recv(self, count):
        chunk = bytes(self.output[:count])
        del self.output[:count]
        return chunk

    def recv_stderr(self, count):
        chunk = bytes(self.errors[:count])
        del self.errors[:count]
        return chunk

    def exit_status_ready(self):
        return not self.never_finish

    def recv_exit_status(self):
        return self.code

    def close(self):
        self.closed = True


class Client:
    def __init__(self, channel):
        self.channel = channel
        self.connect_calls = []
        self.exec_calls = []
        self.keys = paramiko.HostKeys()
        self.policy = None
        self.closed = threading.Event()
        self.connect_error = None

    def set_missing_host_key_policy(self, policy):
        self.policy = policy

    def get_host_keys(self):
        return self.keys

    def connect(self, address, **kwargs):
        self.connect_calls.append((address, kwargs))
        if self.connect_error:
            raise self.connect_error

    def exec_command(self, command, **kwargs):
        self.exec_calls.append((command, kwargs))
        stream = SimpleNamespace(channel=self.channel)
        return stream, stream, stream

    def close(self):
        self.closed.set()


@pytest.fixture
def client(monkeypatch):
    value = Client(Channel())
    monkeypatch.setattr(patch_client.paramiko, "SSHClient", lambda: value)
    return value


def test_fixed_non_root_entry_uses_only_repair_key_and_verified_host(target, client):
    response = invoke(target, request())
    assert response == {"status": "complete"}
    assert isinstance(client.policy, paramiko.RejectPolicy)
    assert client.keys.lookup("192.0.2.20")
    address, options = client.connect_calls[0]
    assert address == "192.0.2.20"
    assert options["username"] == "opsark-repair"
    assert options["key_filename"] == str(target.key_file)
    assert options["look_for_keys"] is False and options["allow_agent"] is False
    assert client.exec_calls[0][0] == "opsark-patch-v1"
    assert client.exec_calls[0][1]["get_pty"] is False
    assert json.loads(client.channel.sent[0]) == request()
    assert client.channel.eof and client.channel.closed and client.closed.is_set()
    assert len(client.connect_calls) == len(client.exec_calls) == 1


def test_changed_known_hosts_is_rejected_before_any_connection(target, client):
    target.host.known_hosts_file.write_text("changed identity\n")
    with pytest.raises(ValueError, match="可信主机记录已变化"):
        invoke(target, request("submit"))
    assert not client.connect_calls and not client.exec_calls


def test_missing_expected_identity_is_not_learned_automatically(target, client):
    host = target.host.public.model_copy(update={"trusted_hosts_digest": None})
    incomplete = PatchTarget(
        host=HostConfig(host, target.host.key_file, target.host.known_hosts_file),
        key_file=target.key_file,
        policy_digest=POLICY,
    )
    with pytest.raises(ValueError, match="可信主机摘要"):
        invoke(incomplete, request())
    assert not client.connect_calls


def test_readonly_key_cannot_be_reused(target):
    with pytest.raises(ValueError, match="独立"):
        PatchTarget(target.host, target.host.key_file, POLICY)


@pytest.mark.parametrize(
    "body",
    [
        request(op="shell"),
        request(schema_version=True),
        request(policy_digest="e" * 64),
        request("submit", job_id="../other"),
        request("submit", mode_revision=True),
        request("submit", mode_revision=-1),
        request("submit", plan_digest="bad"),
        request("submit", command="apt-get upgrade"),
        request(extra="x" * 16384),
        request(extra=float("nan")),
    ],
)
def test_invalid_requests_never_open_an_ssh_connection(target, client, body):
    with pytest.raises(ValueError):
        invoke(target, body)
    assert not client.connect_calls


@pytest.mark.parametrize("timeout", [True, 0, -1, 181, float("nan"), float("inf")])
def test_timeout_is_bounded_and_not_a_boolean(target, client, timeout):
    with pytest.raises(ValueError):
        invoke(target, request(), timeout=timeout)
    assert not client.connect_calls


def test_lost_submit_response_is_unknown_and_never_retried(target, client):
    client.channel.fail_send = True
    with pytest.raises(UnknownPatchResult) as caught:
        invoke(target, request("submit"))
    assert caught.value.job_id == JOB and caught.value.op == "submit"
    assert "private transport error" not in str(caught.value)
    assert len(client.connect_calls) == len(client.exec_calls) == 1
    assert len(client.channel.sent) == 1


def test_non_mutating_transport_loss_does_not_claim_a_patch_ran(target, client):
    client.channel.fail_send = True
    with pytest.raises(PatchClientError) as caught:
        invoke(target, request("status", job_id=JOB))
    assert not isinstance(caught.value, UnknownPatchResult)


def test_submit_connection_deadline_preserves_original_id_as_unknown(target, client):
    client.connect_error = TimeoutError("synthetic connection deadline")
    with pytest.raises(UnknownPatchResult) as caught:
        invoke(target, request("submit"))
    assert caught.value.job_id == JOB
    assert len(client.connect_calls) == 1 and not client.exec_calls


def test_authentication_failure_is_definite_and_private(target, client):
    client.connect_error = paramiko.AuthenticationException("private credential path")
    with pytest.raises(PatchClientError) as caught:
        invoke(target, request("submit"))
    assert not isinstance(caught.value, UnknownPatchResult)
    assert "private credential path" not in str(caught.value)
    assert not client.exec_calls


@pytest.mark.parametrize(
    "output",
    [
        b"[]",
        b'{"status":"verified","status":"unknown"}',
        b'{"number":NaN}',
        b"not-json",
        b"\xff",
        b'{"host_id":"other-host"}',
        ('{"policy_digest":"' + "e" * 64 + '"}').encode(),
    ],
)
def test_untrustworthy_submit_reply_is_unknown(target, client, output):
    client.channel.output = bytearray(output)
    with pytest.raises(UnknownPatchResult):
        invoke(target, request("submit"))
    assert len(client.exec_calls) == 1


def test_stdout_and_stderr_have_separate_hard_budgets(target, client, monkeypatch):
    monkeypatch.setattr(patch_client, "MAX_OUTPUT_BYTES", 64)
    client.channel.output = bytearray(b"x" * 65)
    with pytest.raises(UnknownPatchResult):
        invoke(target, request("submit"))
    client.channel = Channel(errors=b"e" * 4097)
    with pytest.raises(PatchClientError):
        invoke(target, request())


@pytest.fixture
def controlled_deadline(monkeypatch):
    class Clock:
        now = 100.0

        def monotonic(self):
            return self.now

        def sleep(self, seconds):
            self.now += seconds

    class Timer:
        def __init__(self, interval, callback):
            self.interval = interval
            self.callback = callback
            self.daemon = False
            self.started = False
            self.cancelled = False

        def start(self):
            self.started = True

        def cancel(self):
            self.cancelled = True

        def fire(self):
            assert self.started and not self.cancelled
            clock.now += self.interval
            self.callback()

    clock = Clock()
    timers = []

    def timer_factory(interval, callback):
        timer = Timer(interval, callback)
        timers.append(timer)
        return timer

    # Replace the module references rather than the process-wide time/threading APIs.
    monkeypatch.setattr(patch_client, "time", clock)
    monkeypatch.setattr(
        patch_client, "threading", SimpleNamespace(Event=threading.Event, Timer=timer_factory)
    )
    return clock, timers


def test_long_exec_ack_is_bounded_by_transport_watchdog(target, client, controlled_deadline):
    _clock, timers = controlled_deadline

    def awaiting_ack(command, **options):
        client.exec_calls.append((command, options))
        timers[0].fire()
        assert client.closed.is_set()
        raise paramiko.SSHException("synthetic exec ACK interrupted by transport close")

    client.exec_command = awaiting_ack
    with pytest.raises(UnknownPatchResult) as caught:
        invoke(target, request("submit"), timeout=1)
    assert caught.value.job_id == JOB
    assert client.closed.is_set() and timers[0].cancelled
    assert len(client.exec_calls) == 1 and client.channel.sent == []


def test_absolute_deadline_also_covers_idle_output(target, client, controlled_deadline):
    clock, timers = controlled_deadline
    client.channel.output.clear()
    client.channel.never_finish = True
    with pytest.raises(UnknownPatchResult) as caught:
        invoke(target, request("submit"), timeout=1)
    assert caught.value.job_id == JOB
    assert client.channel.closed and client.closed.is_set()
    assert len(client.exec_calls) == len(client.channel.sent) == 1
    assert clock.now >= 101 and timers[0].cancelled


def test_deadline_before_channel_creation_closes_transport_without_sending(
    target, client, controlled_deadline
):
    clock, timers = controlled_deadline
    connect = client.connect

    def delayed_connect(address, **options):
        connect(address, **options)
        clock.now += 2

    client.connect = delayed_connect
    with pytest.raises(UnknownPatchResult) as caught:
        invoke(target, request("submit"), timeout=1)
    assert caught.value.job_id == JOB
    assert client.closed.is_set() and timers[0].cancelled
    assert not client.exec_calls and not client.channel.sent


def test_unexpected_exit_never_turns_into_a_successful_submit(target, client):
    client.channel.code = 1
    with pytest.raises(UnknownPatchResult):
        invoke(target, request("submit"))


def test_valid_json_and_status_without_eof_still_obey_original_deadline(
    target, client, controlled_deadline
):
    clock, timers = controlled_deadline
    client.channel.output = bytearray(b'{"status":"verified"}')
    client.channel.eof_received = False
    with pytest.raises(UnknownPatchResult) as caught:
        invoke(target, request("submit"), timeout=1)
    assert caught.value.job_id == JOB
    assert len(client.connect_calls) == len(client.exec_calls) == len(client.channel.sent) == 1
    assert clock.now >= 101 and timers[0].cancelled
    assert client.channel.closed and client.closed.is_set()


def test_eof_without_status_never_calls_a_blocking_status_reader(
    target, client, controlled_deadline
):
    clock, timers = controlled_deadline
    client.channel.output = bytearray(b'{"status":"verified"}')
    client.channel.eof_received = True
    client.channel.never_finish = True
    client.channel.recv_exit_status = lambda: pytest.fail("Status reader would block")
    with pytest.raises(UnknownPatchResult) as caught:
        invoke(target, request("submit"), timeout=1)
    assert caught.value.job_id == JOB
    assert len(client.exec_calls) == len(client.channel.sent) == 1
    assert clock.now >= 101 and timers[0].cancelled


def test_closed_channel_without_eof_or_transport_preserves_original_unknown(target, client):
    client.channel.output = bytearray(b'{"status":"verified"}')
    client.channel.eof_received = False
    client.channel.closed = True
    client.channel.get_transport = lambda: None
    with pytest.raises(UnknownPatchResult) as caught:
        invoke(target, request("submit"))
    assert caught.value.job_id == JOB
    assert isinstance(caught.value.__cause__, EOFError)
    assert len(client.exec_calls) == len(client.channel.sent) == 1
