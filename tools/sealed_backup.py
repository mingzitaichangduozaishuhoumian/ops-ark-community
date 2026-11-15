"""Seal verified offline controller snapshots; never contact a model or remote service."""

import argparse
import contextlib
import hashlib
import importlib.util
import json
import os
import re
import secrets
import subprocess
import sys
from pathlib import Path
from threading import Thread

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))
from tools import _sealed_archive as archive  # noqa: E402 -- isolated CLI package root.
from tools import _sealed_paths as paths  # noqa: E402 -- isolated CLI package root.

AGE_VERSION = "v1.3.2"
MAX_CIPHERTEXT_BYTES = archive.MAX_PLAINTEXT_BYTES + 4 * 1024 * 1024
RECIPIENT = re.compile(rb"age1[qpzry9x8gf2tvdw0s3jn54khce6mua7l]{58}(?:\r?\n)?\Z")
HEX = re.compile(r"[0-9a-f]{64}\Z")


class BackupError(ValueError):
    """Only a fixed failure category, never source data or native stderr."""


class _Parser(argparse.ArgumentParser):
    def error(self, message):
        raise BackupError("invalid_cli_arguments")


def _require(condition, code):
    if not condition:
        raise BackupError(code)


def _hash(source):
    source.verify()
    source.handle.seek(0)
    digest = hashlib.sha256()
    while part := source.handle.read(65536):
        digest.update(part)
    source.verify()
    source.handle.seek(0)
    return digest.hexdigest()


def _sha(value):
    _require(isinstance(value, str) and HEX.fullmatch(value), "invalid_expected_digest")
    return value


def _environment():
    # Go's native executables need no user configuration or inherited credentials.
    if os.name == "nt":
        root = os.environ.get("SYSTEMROOT", r"C:\Windows")
        return {"SystemRoot": root, "PATH": str(Path(root) / "System32")}
    return {"PATH": "/usr/bin:/bin", "LC_ALL": "C"}


def _native(
    arguments,
    *,
    stdin=None,
    output=None,
    consume=None,
    produce=None,
    timeout=300,
    executable_handle=None,
):
    _require(output is not None or consume is not None, "native_output_must_be_captured")
    if executable_handle is None:
        raise BackupError("held_native_executable_required")
    descriptor = executable_handle.fileno()
    executable = f"/proc/self/fd/{descriptor}" if sys.platform == "linux" else arguments[0]
    errors, values = [], []
    with subprocess.Popen(  # noqa: S603 -- verified native executable, fixed argv, no shell.
        arguments,
        executable=executable,
        stdin=subprocess.PIPE if produce else (stdin or subprocess.DEVNULL),
        stdout=subprocess.PIPE if consume else output,
        stderr=subprocess.PIPE,
        env=_environment(),
        creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        start_new_session=os.name != "nt",
        pass_fds=(descriptor,) if sys.platform == "linux" else (),
    ) as process:

        def fail():
            with contextlib.suppress(OSError):
                process.kill()

        def stderr():
            try:
                if process.stderr is None:
                    raise BackupError("native_stderr_unavailable")
                total = 0
                while part := process.stderr.read(1024):
                    total += len(part)
                    if total > 4096:
                        raise BackupError("native_error_budget")
                # Stderr never leaves this process, including on failure.
            except Exception:
                errors.append("native_error_budget")
                fail()

        def producer():
            try:
                if produce is None or process.stdin is None:
                    raise BackupError("native_stdin_unavailable")
                produce(process.stdin)
                process.stdin.close()
            except Exception:
                errors.append("native_input_failed")
                with contextlib.suppress(OSError):
                    if process.stdin is not None:
                        process.stdin.close()
                fail()

        def consumer():
            try:
                if consume is None or process.stdout is None:
                    raise BackupError("native_stdout_unavailable")
                values.append(consume(process.stdout))
            except Exception:
                errors.append("native_output_refused")
                fail()

        threads = [Thread(target=stderr, daemon=True)]
        if produce:
            threads.append(Thread(target=producer, daemon=True))
        if consume:
            threads.append(Thread(target=consumer, daemon=True))
        for thread in threads:
            thread.start()
        try:
            code = process.wait(timeout=timeout)
        except subprocess.TimeoutExpired as error:
            fail()
            process.wait(timeout=5)
            raise BackupError("native_time_budget") from error
        finally:
            for thread in threads:
                thread.join(timeout=5)
        _require(all(not t.is_alive() for t in threads), "native_io_incomplete")
        _require(code == 0 and not errors, "native_operation_failed")
        return values[0] if consume else None


def _bounded_read(stream, limit):
    value = stream.read(limit + 1)
    _require(len(value) <= limit and not stream.read(1), "native_output_budget")
    return value


class _Bounded:
    def __init__(self, stream):
        self.stream, self.count = stream, 0

    def read(self, size=-1):
        _require(type(size) is int and 0 <= size <= 65536, "bounded_stream_read_required")
        part = self.stream.read(size)
        self.count += len(part)
        _require(self.count <= archive.MAX_PLAINTEXT_BYTES, "plaintext_stream_budget")
        return part


def _discard(stream):
    bounded = _Bounded(stream)
    while bounded.read(65536):
        pass
    return bounded.count


def _dependency(stack, executable, expected):
    executable = stack.enter_context(paths.executable_namespace(executable))
    paths.verify_executable(executable, _sha(expected))
    held = stack.enter_context(paths.held_file(executable, 32 * 1024 * 1024, private=False))
    _require(_hash(held) == _sha(expected), "native_binary_digest_mismatch")
    version = _native(
        [str(executable), "--version"],
        consume=lambda s: _bounded_read(s, 64),
        timeout=5,
        executable_handle=held.handle,
    )
    _require(version.strip() == AGE_VERSION.encode("ascii"), "unsupported_native_version")
    held.verify()
    return held


def _store_transfer():
    spec = importlib.util.spec_from_file_location(
        "opsark_sealed_store_transfer", ROOT / "deploy/observer/store_transfer.py"
    )
    if spec is None or spec.loader is None:
        raise BackupError("store_transfer_module_unavailable")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    _require(tuple(module.DATABASES) == archive.DATABASES, "ten_store_contract_changed")
    return module


def _cipher_header(source):
    source.verify()
    source.handle.seek(0)
    lines = [source.handle.readline(128) for _ in range(4)]
    _require(
        lines[0] == b"age-encryption.org/v1\n"
        and re.fullmatch(rb"-> X25519 [A-Za-z0-9+/]{43}\n", lines[1])
        and re.fullmatch(rb"[A-Za-z0-9+/]{43}\n", lines[2])
        and re.fullmatch(rb"--- [A-Za-z0-9+/]{43}\n", lines[3]),
        "only_single_native_x25519_ciphertext",
    )
    _require(source.size >= sum(map(len, lines)) + 32, "ciphertext_truncated")
    source.handle.seek(0)


def _proof(manifest, cipher_digest, cipher_bytes):
    return {
        "schema_version": manifest["schema_version"],
        "backup_id": manifest["backup_id"],
        "profile": manifest["profile"],
        "cipher_sha256": cipher_digest,
        "cipher_bytes": cipher_bytes,
        "database_count": 10,
        "file_count": len(manifest["files"]),
        "snapshot_verified": True,
        "configuration_included": manifest["profile"] != "stores-v1",
        "inline_config_secrets_may_be_present": manifest["profile"] != "stores-v1",
        "image_material_included": manifest["image_material_included"],
        "credential_files_included": False,
        "remote_root_state_included": False,
        "quiescence_operator_confirmed": True,
    }


def _exists(path):
    return path.exists() or path.is_symlink() or path.is_junction()


def _sources(stack, snapshot, profile, config_root):
    sources, image_included = {}, False
    for name in sorted(archive.CORE):
        sources[name] = stack.enter_context(
            paths.held_file(snapshot / name.removeprefix("stores/"), archive.member_limit(name))
        )
    if profile != "stores-v1":
        _require(config_root is not None, "configuration_root_required")
        config_root = paths.private_directory(config_root)
        record = stack.enter_context(
            paths.held_file(config_root / "handover.json", 65536, private=False)
        )
        raw = record.handle.read(65537)
        record.verify()
        plan, names = archive.handover_plan(raw, profile)
        # Every handover profile must notice all known fixed configuration paths.
        # v1 cannot claim complete configuration while silently omitting a newer
        # defense registration; its archive member allowlist remains unchanged.
        configs = archive.CONFIGS | archive.defense.CONFIGS
        for candidate in configs:
            present = _exists(config_root / candidate)
            if profile == "observer-handover-v1" and candidate in archive.defense.CONFIGS:
                _require(not present, "defense_configuration_requires_v2")
            _require(
                present == (candidate in names),
                "unregistered_or_missing_configuration",
            )
        sources["config-original/handover.json"] = record
        for relative in sorted(names - {"handover.json"}):
            name = "config-original/" + relative
            sources[name] = stack.enter_context(
                paths.held_file(config_root / relative, archive.member_limit(name), private=False)
            )
        image_included = plan["image"]["material"] == "embedded_archive"
        image = config_root / archive.IMAGE
        _require(_exists(image) == image_included, "image_material_scope_mismatch")
        if image_included:
            held = stack.enter_context(
                paths.held_file(image, archive.MAX_IMAGE_BYTES, private=False)
            )
            _require(
                _hash(held) == plan["image"]["archive_sha256"], "image_archive_digest_mismatch"
            )
            sources[archive.IMAGE] = held
        if profile == archive.defense.PROFILE:
            documents = {}
            for name in names:
                held = sources["config-original/" + name]
                held.handle.seek(0)
                documents[name] = held.handle.read(
                    archive.member_limit("config-original/" + name) + 1
                )
                held.verify()
            archive.defense.validate_bundle(plan, documents)
    else:
        _require(config_root is None, "stores_profile_excludes_configuration")
    rows = [
        {
            "name": name,
            "size": source.size,
            "sha256": _hash(source),
            "permissions": source.permissions,
        }
        for name, source in sorted(sources.items())
    ]
    return sources, rows, image_included


def seal(
    snapshot: Path,
    recipient_file: Path,
    expected_recipient_sha256: str,
    age_bin: Path,
    expected_age_sha256: str,
    output: Path,
    *,
    profile="stores-v1",
    config_root=None,
    confirm_quiescent=False,
):
    try:
        _require(
            profile in archive.PROFILES and confirm_quiescent is True,
            "profile_and_quiescence_confirmation_required",
        )
        snapshot = paths.private_directory(snapshot)
        output = paths.validate_destination(output)
        _require(
            output.name.endswith(".age")
            and not output.is_relative_to(snapshot)
            and (config_root is None or not output.is_relative_to(config_root)),
            "separate_new_ciphertext_required",
        )
        transfer = _store_transfer()
        before = transfer.verify_snapshot(snapshot)
        with contextlib.ExitStack() as stack:
            native = _dependency(stack, age_bin, expected_age_sha256)
            recipient = stack.enter_context(paths.held_file(recipient_file, 128, private=False))
            _require(
                _hash(recipient) == _sha(expected_recipient_sha256), "recipient_digest_mismatch"
            )
            raw = recipient.handle.read(129)
            _require(RECIPIENT.fullmatch(raw), "single_classic_public_recipient_required")
            public = raw.strip().decode("ascii")
            sources, rows, image = _sources(stack, snapshot, profile, config_root)
            manifest = archive.make_manifest("sb-" + secrets.token_hex(16), profile, rows, image)
            with paths.new_workspace(output.parent, "sealed-") as workspace:
                pending = workspace / "payload.age"
                with paths.new_file(pending) as destination:
                    _native(
                        [str(age_bin), "--encrypt", "--recipient", public],
                        output=destination,
                        produce=lambda stream: archive.write_archive(stream, manifest, sources),
                        executable_handle=native.handle,
                    )
                    destination.flush()
                    os.fsync(destination.fileno())
                native.verify()
                recipient.verify()
                _require(transfer.verify_snapshot(snapshot) == before, "snapshot_changed")
                for source in sources.values():
                    source.verify()
                with paths.held_file(pending, MAX_CIPHERTEXT_BYTES) as cipher:
                    _cipher_header(cipher)
                    digest, count = _hash(cipher), cipher.size
                paths.publish_file(pending, output)
                return {
                    **_proof(manifest, digest, count),
                    "sealed": True,
                    "plaintext_tar_written": False,
                }
    except BackupError:
        raise
    except Exception as error:
        raise BackupError("seal_refused") from error


def check_ciphertext(input: Path, expected_sha256: str):
    try:
        with paths.held_file(input, MAX_CIPHERTEXT_BYTES, private=False) as source:
            digest = _hash(source)
            _require(digest == _sha(expected_sha256), "ciphertext_digest_mismatch")
            _cipher_header(source)
            return {
                "schema_version": 1,
                "cipher_sha256": digest,
                "cipher_bytes": source.size,
                "ciphertext_matched": True,
                "content_authenticated": False,
            }
    except BackupError:
        raise
    except Exception as error:
        raise BackupError("ciphertext_check_refused") from error


def _extract_archive(stream, destination, expected_profile=None):
    manifest = archive.extract_archive(_Bounded(stream), destination, paths)
    _require(
        expected_profile is None or manifest["profile"] == expected_profile,
        "restored_profile_mismatch",
    )
    return manifest


def restore(
    input: Path,
    expected_sha256: str,
    identity_file: Path,
    age_bin: Path,
    expected_age_sha256: str,
    age_keygen_bin: Path,
    expected_age_keygen_sha256: str,
    output: Path,
):
    try:
        output = paths.validate_destination(output)
        with contextlib.ExitStack() as stack:
            native = _dependency(stack, age_bin, expected_age_sha256)
            keygen = _dependency(stack, age_keygen_bin, expected_age_keygen_sha256)
            source = stack.enter_context(
                paths.held_file(input, MAX_CIPHERTEXT_BYTES, private=False)
            )
            digest = _hash(source)
            _require(digest == _sha(expected_sha256), "ciphertext_digest_mismatch")
            _cipher_header(source)
            identity = stack.enter_context(paths.held_file(identity_file, 8192))
            public = _native(
                [str(age_keygen_bin), "-y"],
                stdin=identity.handle,
                consume=lambda stream: _bounded_read(stream, 128),
                timeout=5,
                executable_handle=keygen.handle,
            )
            _require(RECIPIENT.fullmatch(public), "single_native_identity_required")
            identity.verify()
            with paths.new_workspace(output.parent, "restore-") as workspace:
                ciphertext = workspace / "payload.age"
                source.handle.seek(0)
                with paths.new_file(ciphertext) as destination:
                    while chunk := source.handle.read(65536):
                        destination.write(chunk)
                    destination.flush()
                    os.fsync(destination.fileno())
                with paths.held_file(ciphertext, MAX_CIPHERTEXT_BYTES) as pinned:
                    _require(_hash(pinned) == digest, "ciphertext_copy_changed")
                    arguments = [str(age_bin), "--decrypt", "--identity", "-", str(ciphertext)]
                    identity.handle.seek(0)
                    authenticated_bytes = _native(
                        arguments,
                        stdin=identity.handle,
                        consume=_discard,
                        executable_handle=native.handle,
                    )
                    identity.verify()
                    pinned.verify()
                    _require(_hash(pinned) == digest, "authenticated_ciphertext_changed")
                    extracted = workspace / "restored"
                    extracted.mkdir(mode=0o700)
                    paths.private_directory(extracted)
                    identity.handle.seek(0)
                    manifest = _native(
                        arguments,
                        stdin=identity.handle,
                        consume=lambda stream: _extract_archive(stream, extracted),
                        executable_handle=native.handle,
                    )
                    identity.verify()
                    native.verify()
                    keygen.verify()
                    pinned.verify()
                    _require(_hash(pinned) == digest, "ciphertext_changed_after_restore")
                    source.verify()
                    transfer = _store_transfer()
                    transfer.verify_snapshot(extracted / "stores")
                    # Completion metadata is local only and never changes any restored store/config.
                    with paths.new_file(extracted / "sealed-manifest.json") as destination:
                        destination.write(archive.canonical(manifest))
                    paths.publish_directory(extracted, output)
                    return {
                        **_proof(manifest, digest, source.size),
                        "restored": True,
                        "full_authentication_before_extraction": True,
                        "authenticated_plaintext_bytes": authenticated_bytes,
                        "configuration_activated": False,
                        "image_loaded": False,
                        "credential_files_restored": False,
                        "leases_cleared": False,
                        "plaintext_tar_written": False,
                    }
    except BackupError:
        raise
    except Exception as error:
        raise BackupError("restore_refused") from error


def main():
    parser = _Parser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    seal_parser = commands.add_parser("seal")
    seal_parser.add_argument("--snapshot", type=Path, required=True)
    seal_parser.add_argument("--recipient-file", type=Path, required=True)
    seal_parser.add_argument("--expected-recipient-sha256", required=True)
    seal_parser.add_argument("--profile", choices=sorted(archive.PROFILES), default="stores-v1")
    seal_parser.add_argument("--config-root", type=Path)
    seal_parser.add_argument("--confirm-quiescent", action="store_true")
    check_parser = commands.add_parser("check-ciphertext")
    restore_parser = commands.add_parser("restore")
    for command in (check_parser, restore_parser):
        command.add_argument("--input", type=Path, required=True)
        command.add_argument("--expected-sha256", required=True)
    for command in (seal_parser, restore_parser):
        command.add_argument("--age-bin", type=Path, required=True)
        command.add_argument("--expected-age-sha256", required=True)
        command.add_argument("--output", type=Path, required=True)
    restore_parser.add_argument("--identity-file", type=Path, required=True)
    restore_parser.add_argument("--age-keygen-bin", type=Path, required=True)
    restore_parser.add_argument("--expected-age-keygen-sha256", required=True)
    try:
        arguments = vars(parser.parse_args())
        operation = arguments.pop("operation")
        result = {"seal": seal, "check-ciphertext": check_ciphertext, "restore": restore}[
            operation
        ](**arguments)
    except Exception:
        print("Sealed backup refused; no recovery was activated.", file=sys.stderr)
        return 1
    print(json.dumps(result, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
