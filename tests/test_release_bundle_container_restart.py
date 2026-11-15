"""The host helper ships as an exact, separate deploy surface."""

import tarfile

from test_release_bundle import bundle
from test_release_bundle import source_commit as source_commit


def test_only_reviewed_container_restart_host_files_are_packaged(tmp_path, source_commit):
    repo, _ = source_commit
    names = {
        "deploy/container/README.md",
        "deploy/container/restart_action.py",
        "deploy/container/restart_journal.py",
        "deploy/container/restart_runtime.py",
        "deploy/container/restart_ssh_entry.py",
    }
    (repo / "deploy/container").mkdir(parents=True)
    for name in names | {"deploy/container/private_policy.py", "deploy/container/unreviewed.conf"}:
        (repo / name).write_text("# Synthetic archive path test\n", encoding="ascii")
    bundle._git(repo, "-c", "core.autocrlf=false", "add", "--", "deploy/container")
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
        "exact container restart files",
    )
    commit = bundle._git(repo, "rev-parse", "HEAD").decode().strip()
    candidate = tmp_path / "container-restart.tar.gz"
    receipt = bundle.build(repo, commit, candidate)
    assert (
        bundle.verify(candidate, expected_commit=commit, expected_sha256=receipt["archive_sha256"])
        == receipt
    )
    with tarfile.open(candidate, "r:gz") as archive:
        assert set(archive.getnames()) == bundle.REQUIRED | {bundle.MANIFEST} | names
