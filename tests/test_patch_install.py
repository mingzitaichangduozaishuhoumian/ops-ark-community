"""A fresh helper hierarchy must stay traversable despite private bootstrap umask."""

import importlib.util
import os
import stat
from pathlib import Path

import pytest


@pytest.mark.skipif(os.name != "posix", reason="Actual POSIX umask and directory traversal modes")
def test_public_helper_ancestor_is_explicitly_traversable_under_private_umask(tmp_path):
    path = Path(__file__).resolve().parents[1] / "deploy/vulnerability/install.py"
    spec = importlib.util.spec_from_file_location("opsark_patch_bootstrap_contract", path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    previous = os.umask(0o077)
    try:
        public = tmp_path / "libexec"
        private = tmp_path / "private-state"
        module.secure_dir(public, 0o755)
        module.secure_dir(private, 0o700)
    finally:
        os.umask(previous)
    assert stat.S_IMODE(public.stat().st_mode) == 0o755
    assert stat.S_IMODE(private.stat().st_mode) == 0o700
