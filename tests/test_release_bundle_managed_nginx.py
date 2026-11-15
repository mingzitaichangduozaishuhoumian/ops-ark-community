"""Ship the reviewed host profiles without broadening the controller image scope."""

import tarfile
from pathlib import Path

from test_release_bundle import bundle
from test_release_bundle import runtime_copy as runtime_copy
from test_release_bundle import source_commit as source_commit


def test_managed_nginx_profiles_are_exact_and_adjacent_conf_is_excluded(
    tmp_path, source_commit, runtime_copy
):
    repo, _ = source_commit
    original, runtime, original_receipt = runtime_copy
    original_proof = bundle.verify_runtime(
        original,
        runtime,
        expected_commit=original_receipt["commit"],
        expected_sha256=original_receipt["archive_sha256"],
    )

    project = Path(__file__).resolve().parents[1]
    names = {
        "deploy/nginx/managed-systemd.conf",
        "deploy/nginx/managed-sshd.conf",
        "deploy/nginx/managed-sudoers.conf",
    }
    expected = {name: (project / name).read_bytes() for name in names}
    unrelated = "deploy/nginx/unreviewed-extra.conf"
    (repo / "deploy/nginx").mkdir(parents=True)
    for name, contents in (expected | {unrelated: b"# Adjacent unreviewed fixture\n"}).items():
        (repo / name).write_bytes(contents)

    bundle._git(repo, "-c", "core.autocrlf=false", "add", "--", "deploy/nginx")
    bundle._git(
        repo,
        "-c",
        "user.name=OpsArk release test",
        "-c",
        "user.email=fixture@example.invalid",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-qm",
        "managed Nginx host profiles",
    )
    commit = bundle._git(repo, "rev-parse", "HEAD").decode().strip()
    candidate = tmp_path / "managed-nginx.tar.gz"
    receipt = bundle.build(repo, commit, candidate)
    assert (
        bundle.verify(candidate, expected_commit=commit, expected_sha256=receipt["archive_sha256"])
        == receipt
    )
    with tarfile.open(candidate, "r:gz") as archive:
        assert set(archive.getnames()) == bundle.REQUIRED | {bundle.MANIFEST} | names
        for name, contents in expected.items():
            stream = archive.extractfile(name)
            assert stream is not None
            with stream:
                assert stream.read() == contents

    proof = bundle.verify_runtime(
        candidate,
        runtime,
        expected_commit=commit,
        expected_sha256=receipt["archive_sha256"],
    )
    assert proof["runtime_file_count"] == original_proof["runtime_file_count"]
    assert proof["runtime_sha256"] == original_proof["runtime_sha256"]
