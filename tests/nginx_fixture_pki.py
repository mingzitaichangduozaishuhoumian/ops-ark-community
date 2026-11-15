"""Create disposable chain material for the networkless Nginx acceptance fixture."""

import os
import secrets
import shutil
import stat
import subprocess
import sys
from contextlib import suppress
from pathlib import Path
from tempfile import TemporaryDirectory

_GID = 65534
_HOSTS = (
    ("target", "target.opsark.invalid"),
    ("control", "control.opsark.invalid"),
    ("default", "unknown.opsark.invalid"),
)
_CA_USAGE = "keyUsage=critical,keyCertSign,cRLSign"
_SUBJECT_KEY_ID = "subjectKeyIdentifier=hash"
_AUTHORITY_KEY_ID = "authorityKeyIdentifier=keyid,issuer"


def _openssl(*args: str) -> None:
    result = subprocess.run(  # noqa: S603 -- fixed OpenSSL commands and disposable fixture paths.
        ["/usr/bin/openssl", *args],
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        timeout=12,
        env={"PATH": "/usr/bin:/bin", "LC_ALL": "C"},
        check=False,
    )
    if result.returncode:
        raise RuntimeError("Could not generate disposable TLS chain material")


def _request(config: Path, name: str, key: Path, output: Path, *options: str) -> None:
    _openssl(
        "req",
        "-config",
        str(config),
        "-newkey",
        "ec",
        "-pkeyopt",
        "ec_paramgen_curve:P-256",
        "-nodes",
        "-subj",
        f"/CN={name}",
        "-keyout",
        str(key),
        "-out",
        str(output),
        *options,
    )


def _issue(
    request: Path,
    certificate: Path,
    issuer: Path,
    issuer_key: Path,
    extensions: Path,
    *,
    days: str,
) -> None:
    _openssl(
        "x509",
        "-req",
        "-in",
        str(request),
        "-CA",
        str(issuer),
        "-CAkey",
        str(issuer_key),
        "-set_serial",
        "0x" + secrets.token_hex(15) + "01",
        "-days",
        days,
        "-sha256",
        "-extfile",
        str(extensions),
        "-out",
        str(certificate),
    )


def _issue_leaf(directory: Path, signer: Path, role: str, hostname: str, *, days: str) -> None:
    request, extensions = signer / "fixture.csr", signer / "extensions.cnf"
    leaf, intermediate = signer / "leaf.pem", signer / "intermediate.pem"
    _request(signer / "request.cnf", hostname, directory / f"{role}-key.pem", request, "-new")
    extensions.write_text(
        "\n".join(
            (
                "basicConstraints=critical,CA:FALSE",
                "keyUsage=critical,digitalSignature",
                "extendedKeyUsage=serverAuth",
                f"subjectAltName=DNS:{hostname}",
                _SUBJECT_KEY_ID,
                _AUTHORITY_KEY_ID,
                "",
            )
        ),
        encoding="ascii",
    )
    _issue(request, leaf, intermediate, signer / "intermediate.key", extensions, days=days)
    # The chain is public material; OpenSSL alone opens private keys.
    with (directory / f"{role}-chain.pem").open("xb") as chain:
        for certificate in (leaf, intermediate):
            with certificate.open("rb") as public:
                shutil.copyfileobj(public, chain)


def _generate(directory: Path, signer: Path, renewed: Path | None) -> None:
    config = signer / "request.cnf"
    config.write_text("[req]\ndistinguished_name=dn\n[dn]\n", encoding="ascii")
    root, root_key = signer / "root.pem", signer / "root.key"
    intermediate, intermediate_key = signer / "intermediate.pem", signer / "intermediate.key"
    request, extensions = signer / "fixture.csr", signer / "extensions.cnf"
    _request(
        config,
        "OpsArk Disposable Root",
        root_key,
        root,
        "-x509",
        "-days",
        "4" if renewed is not None else "3",
        "-sha256",
        "-addext",
        "basicConstraints=critical,CA:TRUE,pathlen:1",
        "-addext",
        _CA_USAGE,
        "-addext",
        _SUBJECT_KEY_ID,
    )
    _request(config, "OpsArk Disposable Intermediate", intermediate_key, request, "-new")
    extensions.write_text(
        "\n".join(
            (
                "basicConstraints=critical,CA:TRUE,pathlen:0",
                _CA_USAGE,
                _SUBJECT_KEY_ID,
                _AUTHORITY_KEY_ID,
                "",
            )
        ),
        encoding="ascii",
    )
    _issue(
        request, intermediate, root, root_key, extensions, days="3" if renewed is not None else "2"
    )
    shutil.copyfile(root, directory / "root.pem")

    for role, hostname in _HOSTS:
        _issue_leaf(directory, signer, role, hostname, days="1")
    if renewed is None:
        return
    shutil.copyfile(directory / "root.pem", renewed / "root.pem")
    for role, hostname in _HOSTS:
        if role == "target":
            _issue_leaf(renewed, signer, role, hostname, days="2")
        else:
            chain_name, key_name = f"{role}-chain.pem", f"{role}-key.pem"
            shutil.copyfile(directory / chain_name, renewed / chain_name)
            _openssl("pkey", "-in", str(directory / key_name), "-out", str(renewed / key_name))


def _generate_private_outputs(directory: Path, renewed: Path | None = None) -> None:
    if sys.platform != "linux" or os.geteuid() != 0:
        raise RuntimeError("TLS chain generation needs a root-owned fixture workspace")
    directories = (directory,) if renewed is None else (directory, renewed)
    if not all(output.is_absolute() for output in directories):
        raise RuntimeError("TLS chain generation needs a root-owned fixture workspace")
    if renewed is not None and (
        directory.parent == renewed.parent
        or directory.is_relative_to(renewed)
        or renewed.is_relative_to(directory)
    ):
        raise RuntimeError("TLS renewal needs separate private fixture workspaces")
    outputs = ("root.pem",) + tuple(
        f"{role}-{suffix}.pem" for role, _ in _HOSTS for suffix in ("chain", "key")
    )
    created = []
    try:
        for output in directories:
            parent = output.parent
            info = parent.lstat()
            if (
                parent.resolve(strict=True) != parent
                or not stat.S_ISDIR(info.st_mode)
                or info.st_uid != 0
                or info.st_mode & 0o077
            ):
                raise RuntimeError("TLS chain generation needs a private fixture workspace")
        for output in directories:
            output.mkdir(mode=0o700)
            created.append(output)
            output.chmod(0o700)
        with TemporaryDirectory(
            prefix=".opsark-fixture-signing-", dir=directory.parent
        ) as temporary:
            _generate(directory, Path(temporary), renewed)
        for output in directories:
            for name in outputs:
                path = output / name
                os.chown(path, 0, _GID)
                path.chmod(0o640)
            os.chown(output, 0, _GID)
            output.chmod(0o750)
    except (OSError, RuntimeError, subprocess.SubprocessError):
        for output in reversed(created):
            for name in outputs:
                with suppress(OSError):
                    (output / name).unlink()
            with suppress(OSError):
                output.rmdir()
        raise RuntimeError("Could not create the isolated synthetic TLS chain") from None


def generate_chain_tls(directory: Path) -> None:
    """Generate three synthetic leaf chains, with only leaf keys in the final tree."""
    _generate_private_outputs(directory)


def generate_renewal_tls(current: Path, renewed: Path) -> None:
    """Generate a separate fixture generation renewing only the target certificate."""
    _generate_private_outputs(current, renewed)
