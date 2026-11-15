"""Exercise the embedded HTTPS probe without opening sockets or private keys."""

import hashlib
import http.client
import importlib
import json
import os
import socket
import ssl
import stat
import subprocess
import sys
from io import BytesIO
from pathlib import Path
from types import SimpleNamespace

import pytest

HOSTS = ("target.opsark.invalid", "control.opsark.invalid", "unknown.opsark.invalid")
LEAF = b"synthetic certificate DER"
DEVICE = 2049
TARGET_INODE = 100
TLS_PATH = Path("/fixture-tls")
CHAIN_ROLES = ("target", "control", "default")


def identity(inode: int, *, mode: int) -> dict[str, int]:
    return {
        "dev": DEVICE,
        "ino": inode,
        "size": 512,
        "mtime_ns": 100,
        "ctime_ns": 200,
        "mode": mode,
        "uid": 0,
        "gid": 65534,
    }


@pytest.fixture
def runtime(monkeypatch):
    monkeypatch.syspath_prepend(str(Path(__file__).resolve().parents[1]))
    return importlib.import_module("deploy.nginx.fixture_runtime")


@pytest.mark.parametrize(
    ("chain_method", "fault", "requests"),
    [
        (None, None, HOSTS),
        (None, "insecure_mode", ()),
        (None, "insecure_directory", ()),
        (None, "different_inode", ()),
        (None, "symlink", ()),
        (None, "hardlink", ()),
        (None, "untrusted_certificate", ()),
        (None, "wrong_leaf_pin", ()),
        (None, "replacement_during_probe", HOSTS),
        ("python", None, HOSTS),
        ("python", "wrong_sni_leaf", ()),
        ("python", "wrong_intermediate", ()),
        ("python", "missing_intermediate", ()),
        ("python", "extra_root", ()),
        ("python", "resumed_session", ()),
        ("openssl", None, HOSTS),
        ("openssl", "wrong_intermediate", ()),
        ("openssl", "reversed_chain", ()),
        ("openssl", "extra_root", ()),
        ("openssl", "missing_section", ()),
        ("openssl", "oversized_transcript", ()),
        ("openssl", "verification_failure", ()),
        ("openssl", "resumed_session", ()),
    ],
)
def test_tls_probe_requires_sealed_key_identity_and_verified_leaf(
    runtime, monkeypatch, capsys, chain_method, fault, requests
):
    events = []
    raw_closed = []
    metadata = {
        "cert.pem": identity(200, mode=0o640),
        "key.pem": identity(201, mode=0o640),
    }
    leaves = {host: LEAF for host in HOSTS}
    intermediates = {host: f"fixture intermediate {host}".encode() for host in HOSTS}
    root = b"synthetic root DER"
    directory = identity(199, mode=0o750)
    opened_files = {
        Path("/fixture-sites") / runtime.TARGET: (TARGET_INODE, runtime.fixture_action.ORIGINAL)
    }
    files = runtime.fixture_context.TLS_FIXTURE_FILES
    trust_path = "/fixture-tls/cert.pem"
    pins = {"cert_sha256": hashlib.sha256(LEAF).hexdigest()}
    if chain_method is not None:
        files = runtime.fixture_context.CHAIN_FIXTURE_FILES
        trust_path = "/fixture-tls/root.pem"
        leaves = {host: f"fixture leaf {host}".encode() for host in HOSTS}
        metadata = {"root.pem": identity(200, mode=0o640)}
        for index, role in enumerate(CHAIN_ROLES, 201):
            metadata[f"{role}-chain.pem"] = identity(index, mode=0o640)
            metadata[f"{role}-key.pem"] = identity(index + len(CHAIN_ROLES), mode=0o640)
        pem = ssl.DER_cert_to_PEM_cert(root).encode("ascii")
        opened_files[Path(trust_path)] = (metadata["root.pem"]["ino"], pem)
        pins = {
            "leaf_sha256": {host: hashlib.sha256(der).hexdigest() for host, der in leaves.items()},
            "intermediate_sha256": {
                host: hashlib.sha256(der).hexdigest() for host, der in intermediates.items()
            },
            "root_pem_sha256": hashlib.sha256(pem).hexdigest(),
        }
    dependencies = []
    for inode, (name, content) in enumerate(files.items(), 101):
        opened_files[Path("/fixture-runtime") / name] = (inode, content)
        dependencies.append([name, hashlib.sha256(content).hexdigest(), DEVICE, inode])
    target_sha = hashlib.sha256(runtime.fixture_action.ORIGINAL).hexdigest()
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "-c",
            target_sha,
            str(DEVICE),
            str(TARGET_INODE),
            json.dumps(dependencies),
            json.dumps({**pins, "directory": directory, "files": metadata}),
        ],
    )

    class MountedFile(BytesIO):
        def __init__(self, inode, data):
            super().__init__(data)
            self.inode = inode

        def fileno(self):
            return self.inode

    def open_fixture(path, mode):
        assert mode == "rb" and path in opened_files, "unexpected file read in TLS probe"
        return MountedFile(*opened_files[path])

    def nofollow_stat(path, *, follow_symlinks):
        assert not follow_symlinks
        if path == TLS_PATH:
            values = directory.copy()
            if fault == "insecure_directory":
                values["mode"] = 0o755
            values["mode"] |= stat.S_IFDIR
            return SimpleNamespace(
                st_nlink=2, **{f"st_{name}": value for name, value in values.items()}
            )
        assert path.parent == TLS_PATH and path.name in metadata
        values = metadata[path.name].copy()
        kind = stat.S_IFREG
        links = 1
        if path.name == "key.pem":
            if fault == "insecure_mode":
                values["mode"] = 0o644
            elif fault == "different_inode" or (
                fault == "replacement_during_probe" and ("http", HOSTS[-1]) in events
            ):
                values["ino"] += 1
            elif fault == "symlink":
                kind = stat.S_IFLNK
            elif fault == "hardlink":
                links = 2
        values["mode"] |= kind
        return SimpleNamespace(
            st_nlink=links, **{f"st_{name}": value for name, value in values.items()}
        )

    def connect(address, *, timeout):
        assert address == ("127.0.0.1", 18087) and timeout == 1
        return SimpleNamespace(close=lambda: raw_closed.append(True))

    def served(host):
        chain = [leaves[host], intermediates[host]]
        if fault == "wrong_intermediate":
            chain[-1] = b"different intermediate"
        elif fault == "missing_intermediate":
            chain.pop()
        elif fault == "extra_root":
            chain.append(root)
        elif fault == "reversed_chain":
            chain.reverse()
        return chain

    class VerifiedSocket:
        def __init__(self, host):
            self.host = host
            self.session_reused = fault == "resumed_session"

        def getpeercert(self, *, binary_form):
            assert binary_form is True
            events.append(("leaf", self.host))
            if fault == "wrong_leaf_pin":
                return b"different certificate"
            if fault == "wrong_sni_leaf":
                return leaves[HOSTS[1]]
            return leaves[self.host]

    class ChainSocket(VerifiedSocket):
        def get_unverified_chain(self):
            events.append(("chain", self.host))
            return served(self.host)

    def openssl(args, **options):
        assert chain_method == "openssl", "unexpected auxiliary chain handshake"
        host = args[args.index("-servername") + 1]
        assert args == [
            "/usr/bin/openssl",
            "s_client",
            "-connect",
            "127.0.0.1:18087",
            "-servername",
            host,
            "-verify_hostname",
            host,
            "-verify_return_error",
            "-verifyCAfile",
            trust_path,
            "-no-CAfile",
            "-no-CApath",
            "-no-CAstore",
            "-showcerts",
            "-no_ticket",
        ]
        assert options == {
            "stdin": subprocess.DEVNULL,
            "stdout": subprocess.PIPE,
            "stderr": subprocess.DEVNULL,
            "env": {"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
            "timeout": 2,
            "check": False,
        }
        events.append(("chain", host))
        wire = b"".join(
            f" {index} fixture certificate\n".encode() + ssl.DER_cert_to_PEM_cert(der).encode()
            for index, der in enumerate(served(host))
        )
        # The server-certificate transcript outside the chain section is deliberately not pinned.
        output = (
            b"CONNECTED\n---\nCertificate chain\n"
            + wire
            + b"---\nServer certificate\n"
            + ssl.DER_cert_to_PEM_cert(root).encode()
        )
        if fault == "missing_section":
            output = output.replace(b"Certificate chain", b"other heading")
        elif fault == "oversized_transcript":
            output += b"x" * 65537
        return SimpleNamespace(returncode=int(fault == "verification_failure"), stdout=output)

    class Context:
        def __init__(self, protocol):
            assert protocol == ssl.PROTOCOL_TLS_CLIENT
            events.append(("context", protocol))

        def load_verify_locations(self, *, cafile):
            assert cafile == trust_path
            events.append(("trust", cafile))

        def wrap_socket(self, raw, *, server_hostname):
            assert self.minimum_version == ssl.TLSVersion.TLSv1_2
            assert getattr(self, "check_hostname", True) is True
            assert getattr(self, "verify_mode", ssl.CERT_REQUIRED) == ssl.CERT_REQUIRED
            assert callable(raw.close) and server_hostname in HOSTS
            events.append(("sni", server_hostname))
            if fault == "untrusted_certificate":
                raise ssl.SSLCertVerificationError
            return (ChainSocket if chain_method == "python" else VerifiedSocket)(server_hostname)

    class Connection:
        def __init__(self, host, port, timeout):
            assert (host, port, timeout) == ("127.0.0.1", 18087, 1)

        def request(self, method, path, *, headers):
            assert (method, path) == ("GET", "/healthz")
            self.host = headers["Host"]
            assert self.sock.host == self.host
            expected = [("sni", self.host), ("leaf", self.host)]
            if chain_method is not None:
                expected.append(("chain", self.host))
            assert events[-len(expected) :] == expected
            events.append(("http", self.host))

        def getresponse(self):
            code, body = {
                HOSTS[0]: (200, b"opsark-original"),
                HOSTS[1]: (200, b"opsark-control"),
                HOSTS[2]: (404, b"fixture default"),
            }[self.host]
            return SimpleNamespace(status=code, read=lambda limit: body[:limit])

        def close(self):
            pass

    code = compile(runtime._PROBE, "<fixture-tls-probe>", "exec")
    with monkeypatch.context() as probe:
        probe.setattr(http.client, "HTTPConnection", Connection)
        probe.setattr(socket, "if_nameindex", lambda: [(1, "lo")])
        probe.setattr(socket, "create_connection", connect)
        probe.setattr(ssl, "SSLContext", Context)
        probe.setattr(subprocess, "run", openssl)
        probe.setattr(Path, "open", open_fixture)
        probe.setattr(Path, "stat", nofollow_stat)
        probe.setattr(os, "fstat", lambda fd: SimpleNamespace(st_dev=DEVICE, st_ino=fd))
        if fault is None:
            exec(code, {})  # noqa: S102 -- fixed probe under mocked I/O
        else:
            with pytest.raises(SystemExit) as error:
                exec(code, {})  # noqa: S102 -- fixed probe under mocked I/O
            assert error.value.code == 1
    assert capsys.readouterr().out == ("original\n" if fault is None else "")
    assert tuple(value for action, value in events if action == "http") == requests
    if fault in {None, "replacement_during_probe"}:
        assert tuple(value for action, value in events if action == "sni") == HOSTS
        assert tuple(value for action, value in events if action == "chain") == (
            HOSTS if chain_method is not None else ()
        )
    elif fault in {"insecure_mode", "insecure_directory", "different_inode", "symlink", "hardlink"}:
        assert not events
    elif fault == "untrusted_certificate":
        assert raw_closed == [True] and ("leaf", HOSTS[0]) not in events
    elif fault in {"wrong_leaf_pin", "wrong_sni_leaf", "resumed_session"}:
        assert events[-2:] == [("sni", HOSTS[0]), ("leaf", HOSTS[0])]
    else:
        assert events[-3:] == [("sni", HOSTS[0]), ("leaf", HOSTS[0]), ("chain", HOSTS[0])]
