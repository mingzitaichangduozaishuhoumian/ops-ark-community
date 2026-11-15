"""The SSH role remains closed in effective config and key provisioning."""

import base64
import json
import os
import sys
from pathlib import Path
from tempfile import TemporaryDirectory

import pytest

from deploy.nginx import managed_role as role
from deploy.nginx import managed_ssh_entry as entry

_DEPLOY = Path(__file__).resolve().parents[1] / "deploy" / "nginx"
_PUBLIC = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
_KEY = b"ssh-ed25519 " + base64.b64encode(role._KEY_PREFIX + _PUBLIC)


def _effective_profile():
    profile = [
        line.strip()
        for line in (_DEPLOY / "managed-sshd.conf").read_bytes().splitlines()
        if line.strip() and not line.lstrip().startswith(b"#")
    ]
    assert profile.pop(0) == b"Match User opsark-nginx-action"
    rows = []
    for line in profile:
        name, value = line.split(maxsplit=1)
        rows.append(name.lower() + b" " + value)
    return (
        b"\n".join(
            [
                *rows,
                b"chrootdirectory none",
                b"permituserenvironment no",
                b"strictmodes yes",
                b"usedns no",
                b"usepam yes",
                b"subsystem sftp /usr/lib/openssh/sftp-server",
            ]
        )
        + b"\n"
    )


def test_key_rendering_has_only_fixed_options_and_drops_comments():
    rendered = role._render_key(_KEY + b" workstation enrollment\r\n")
    assert rendered == b'restrict,command="' + role.SSH_ENTRY.encode() + b'" ' + _KEY + b"\n"
    assert role._render_key(_KEY) == rendered
    assert role._render_key(_KEY + b"\n") == rendered


@pytest.mark.parametrize(
    "raw",
    [
        _KEY + b"\n" + _KEY + b"\n",
        _KEY + b"\n\n",
        b'command="/bin/false" ' + _KEY,
        _KEY.replace(b"ssh-ed25519", b"ssh-ed25519-cert-v01@openssh.com"),
        b"ssh-ed25519 " + base64.b64encode(b"\0" * 51),
        b"ssh-ed25519 " + base64.b64encode(role._KEY_PREFIX + b"\0" * 32),
        _KEY + b" bad\x00comment",
    ],
)
def test_refuses_noncanonical_or_ambiguous_key_input(raw):
    with pytest.raises(role.RoleRefused, match="one dedicated Ed25519 public key"):
        role._render_key(raw)


def test_effective_role_proof_does_not_claim_authentication():
    assert role.verify_effective(_effective_profile()) == {
        "schema_version": 1,
        "role": "opsark-nginx-action",
        "effective_policy_verified": True,
        "authentication_verified": False,
    }


@pytest.mark.parametrize(
    ("original", "replacement"),
    [
        (b"authenticationmethods publickey", b"authenticationmethods any"),
        (
            b"pubkeyacceptedalgorithms ssh-ed25519",
            b"pubkeyacceptedalgorithms ssh-ed25519,rsa-sha2-512",
        ),
        (b"authorizedkeysfile ", b"authorizedkeysfile .ssh/authorized_keys "),
        (b"authorizedkeyscommand none", b"authorizedkeyscommand /bin/false"),
        (b"trustedusercakeys none", b"trustedusercakeys /etc/ssh/other-ca.pub"),
        (b"forcecommand ", b"forcecommand /bin/false "),
        (b"disableforwarding yes", b"disableforwarding no"),
        (b"permittunnel no", b"permittunnel ethernet"),
        (b"permittty no", b"permittty yes"),
        (b"permituserrc no", b"permituserrc yes"),
        (b"permituserenvironment no", b"permituserenvironment yes"),
        (b"strictmodes yes", b"strictmodes no"),
        (b"usedns no", b"usedns yes"),
        (b"acceptenv OPSARK_UNUSED", b"acceptenv *"),
    ],
)
def test_effective_role_rejects_wider_settings(original, replacement):
    raw = _effective_profile()
    assert original in raw
    with pytest.raises(role.RoleRefused, match="could not be verified"):
        role.verify_effective(raw.replace(original, replacement))


@pytest.mark.parametrize(
    "addition",
    [b"acceptenv *\n", b"acceptenv OPSARK_UNUSED\n", b"setenv OTHER=1\n", b"rdomain other\n"],
)
def test_effective_role_rejects_appended_match_values(addition):
    with pytest.raises(role.RoleRefused):
        role.verify_effective(_effective_profile() + addition)


def test_effective_role_rejects_missing_fields():
    with pytest.raises(role.RoleRefused):
        role.verify_effective(_effective_profile().replace(b"passwordauthentication no\n", b""))


def test_sudoers_profile_is_exactly_the_existing_wrapper_target():
    rules = [
        line
        for line in (_DEPLOY / "managed-sudoers.conf").read_text(encoding="ascii").splitlines()
        if line and not line.startswith("#")
    ]
    assert role.ROOT_ACTION == entry.ROOT_ACTION
    assert rules == [
        "Defaults:opsark-nginx-action env_reset",
        "opsark-nginx-action ALL=(root) NOPASSWD: NOSETENV: "
        f"/usr/bin/python3 -I -B {entry.ROOT_ACTION}",
    ]


def test_preflight_uses_exact_role_and_numeric_listener():
    assert role.preflight_argv("2001:db8::1", "2001:db8::2", 2222) == (
        "/usr/sbin/sshd",
        "-T",
        "-C",
        "user=opsark-nginx-action,host=2001:db8::1,addr=2001:db8::1,laddr=2001:db8::2,lport=2222",
    )
    for peer, local, port in (
        ("host.invalid", "192.0.2.1", 22),
        ("192.0.2.1,user=other", "192.0.2.1", 22),
        ("fe80::2%scope", "192.0.2.1", 22),
        ("192.0.2.2", "192.0.2.1", True),
        ("192.0.2.2", "192.0.2.1", 65536),
    ):
        with pytest.raises(role.RoleRefused):
            role.preflight_argv(peer, local, port)


def test_check_cli_prints_only_a_closed_proof_or_generic_error(monkeypatch, capsys):
    monkeypatch.setattr(role, "_local_administrator", lambda: True)
    seen = []

    def read(peer, local, port):
        seen.append((peer, local, port))
        return _effective_profile()

    monkeypatch.setattr(role, "_read_effective", read)
    args = ["check-effective", "--peer", "192.0.2.1", "--local", "192.0.2.2", "--port", "22"]
    assert role.main(args) == 0
    result = capsys.readouterr()
    assert not result.err and seen == [("192.0.2.1", "192.0.2.2", 22)]
    assert json.loads(result.out) == role.verify_effective(_effective_profile())

    monkeypatch.setattr(
        role, "_read_effective", lambda *_: _effective_profile() + b"setenv BLOCKED=fake-local\n"
    )
    assert role.main(args) == 126
    result = capsys.readouterr()
    assert not result.out and result.err == role._REFUSED
    assert role.main(args + ["--peer", "192.0.2.3"]) == 126
    result = capsys.readouterr()
    assert not result.out and result.err == role._REFUSED


@pytest.mark.skipif(sys.platform != "linux", reason="Requires a selectable Linux child pipe")
@pytest.mark.parametrize(
    ("code", "seconds"),
    [
        ("print('x' * 32769)", 5),
        ("import time; time.sleep(2)", 0.25),
        ("raise SystemExit(1)", 5),
    ],
)
def test_native_check_output_and_time_are_bounded(monkeypatch, code, seconds):
    monkeypatch.setattr(role, "preflight_argv", lambda *_: (sys.executable, "-I", "-B", "-c", code))
    monkeypatch.setattr(role, "_CHECK_SECONDS", seconds)
    with pytest.raises(role.RoleRefused, match="could not be verified"):
        role._read_effective("192.0.2.1", "192.0.2.2", 22)


@pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="Requires actual Linux root path ownership",
)
def test_stage_cli_is_private_silent_and_never_overwrites(monkeypatch, capsys):
    with TemporaryDirectory(prefix=".opsark-stage-role-", dir="/root") as root:
        directory = Path(root)
        public_key = directory / "enrollment.pub"
        staged = directory / "authorized_keys.staged"
        public_key.write_bytes(_KEY + b"\n")
        monkeypatch.setattr(role, "STAGED_KEY", staged)
        args = ["stage-key", "--public-key", str(public_key)]

        assert role.main(args) == 0
        captured = capsys.readouterr()
        assert not captured.out and not captured.err
        rendered = role._render_key(_KEY)
        assert staged.read_bytes() == rendered
        info = staged.stat()
        assert info.st_uid == 0 and info.st_gid == 0 and info.st_nlink == 1
        assert info.st_mode & 0o777 == 0o600

        assert role.main(args) == 126
        captured = capsys.readouterr()
        assert not captured.out and captured.err == role._REFUSED
        assert staged.read_bytes() == rendered and staged.stat().st_ino == info.st_ino

        staged.unlink()
        protected = directory / "other"
        protected.write_bytes(b"existing file\n")
        staged.symlink_to(protected)
        assert role.main(args) == 126
        captured = capsys.readouterr()
        assert not captured.out and captured.err == role._REFUSED
        assert staged.is_symlink() and protected.read_bytes() == b"existing file\n"
        assert not list(directory.glob(".pending-key-*"))


@pytest.mark.skipif(
    sys.platform != "linux" or os.geteuid() != 0,
    reason="Requires actual Linux root path ownership",
)
def test_read_public_key_refuses_writable_symlink_and_hardlinked_paths():
    with TemporaryDirectory(prefix=".opsark-public-role-", dir="/root") as root:
        key = Path(root) / "enrollment.pub"
        key.write_bytes(_KEY + b"\n")
        key.chmod(0o644)
        assert role.authorization_from_file(key) == role._render_key(_KEY)
        key.chmod(0o666)
        with pytest.raises(role.RoleRefused, match="public key input unavailable"):
            role.authorization_from_file(key)
        key.chmod(0o644)
        alias = Path(root) / "alias.pub"
        alias.symlink_to(key)
        with pytest.raises(role.RoleRefused, match="public key input unavailable"):
            role.authorization_from_file(alias)
        os.link(key, Path(root) / "duplicate.pub")
        with pytest.raises(role.RoleRefused, match="public key input unavailable"):
            role.authorization_from_file(key)
