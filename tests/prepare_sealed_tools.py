"""Prepare hash-pinned native tools for fake-data backup acceptance, never deployments."""

import argparse
import hashlib
import json
import os
import platform
import shutil
import subprocess
import tarfile
import tempfile
import zipfile
from pathlib import Path

VERSION = "v1.3.2"
ASSETS = {
    "Linux": (
        "age-v1.3.2-linux-amd64.tar.gz",
        "cbe24006683f8eb669266162894b9a522a1af52f2665fbc63a4bb032ed26ac10",
        {
            "age": "eb7dd1b518f0a307c99cd97782623c5321da049154b04acd2d98d21aa7bc9b2c",
            "age-keygen": "0a0009db842259d6717f7eeb30acb6b90d2a2eb924c6acd0a0db0ca1f1537899",
        },
    ),
    "Windows": (
        "age-v1.3.2-windows-amd64.zip",
        "f48d8f8f9ebe903ab5027ed067652f2cc1db94bc206976430133b905dcd8e8c7",
        {
            "age.exe": "2821a4ed191da07372acd302e5f6feae7a7985e285e1417765ebe74025af45f0",
            "age-keygen.exe": "1549c7049be32695594bedd09bbd352a94b6013a9d5c43364f3c6cd7a09ab61c",
        },
    ),
}
LIMIT = 32 * 1024 * 1024


def require(condition):
    if not condition:
        raise ValueError("Pinned acceptance tools could not be prepared")


def extract(archive, output, system):
    asset, expected_archive, binaries = ASSETS[system]
    require(archive.name == asset and archive.is_file() and archive.stat().st_size <= LIMIT)
    require(hashlib.sha256(archive.read_bytes()).hexdigest() == expected_archive)
    values = {}
    if system == "Windows":
        with zipfile.ZipFile(archive) as source:
            for name in binaries:
                matches = [m for m in source.infolist() if m.filename == "age/" + name]
                require(len(matches) == 1 and matches[0].file_size <= LIMIT)
                values[name] = source.read(matches[0])
    else:
        with tarfile.open(archive, "r:gz") as source:
            for name in binaries:
                matches = [m for m in source.getmembers() if m.name == "age/" + name]
                require(len(matches) == 1 and matches[0].isfile() and matches[0].size <= LIMIT)
                stream = source.extractfile(matches[0])
                if stream is None:
                    raise ValueError("Pinned acceptance member is unavailable")
                with stream:
                    values[name] = stream.read(LIMIT + 1)
    require(all(hashlib.sha256(values[n]).hexdigest() == sha for n, sha in binaries.items()))
    output.mkdir(mode=0o700)
    for name, value in values.items():
        descriptor = os.open(output / name, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o700)
        with os.fdopen(descriptor, "wb") as destination:
            destination.write(value)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    destination = parser.add_mutually_exclusive_group(required=True)
    destination.add_argument("--output", type=Path)
    destination.add_argument("--ci-home", action="store_true", help="Use a new CI home directory")
    parser.add_argument("--archive", type=Path, help="Use an already downloaded pinned archive")
    args = parser.parse_args()
    system = platform.system()
    require(system in ASSETS and platform.machine().lower() in {"amd64", "x86_64"})
    output = (Path.home() / "opsark-sealed-tools-ci" if args.ci_home else args.output).absolute()
    require(output.parent.is_dir() and not output.exists() and not output.is_symlink())
    if args.archive:
        extract(args.archive.absolute(), output, system)
    else:
        executable = shutil.which("gh")
        if executable is None:
            raise ValueError("Authenticated GitHub CLI is required for acceptance setup")
        with tempfile.TemporaryDirectory(prefix="opsark-age-asset-", dir=output.parent) as scratch:
            result = subprocess.run(  # noqa: S603 -- fixed official public release and asset.
                [
                    executable,
                    "release",
                    "download",
                    VERSION,
                    "--repo",
                    "FiloSottile/age",
                    "--pattern",
                    ASSETS[system][0],
                    "--dir",
                    scratch,
                ],
                stdin=subprocess.DEVNULL,
                capture_output=True,
                timeout=180,
                check=False,
            )
            require(result.returncode == 0)
            extract(Path(scratch) / ASSETS[system][0], output, system)
    environment = os.environ.get("GITHUB_ENV")
    if environment:
        require("\n" not in str(output) and "\r" not in str(output))
        with Path(environment).open("a", encoding="utf-8") as file:
            file.write("OPSARK_TEST_AGE_DIR=" + str(output) + "\n")
    print(json.dumps({"version": VERSION, "pinned_binaries": 2, "identity_generated": False}))


if __name__ == "__main__":
    main()
