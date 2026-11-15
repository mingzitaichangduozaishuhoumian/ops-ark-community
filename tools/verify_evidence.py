"""Verify a downloaded OpsArk evidence bundle locally; never contact a target or model."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from opsark.vulnerability_evidence import main  # noqa: E402 -- repository-local entry point.

if __name__ == "__main__":
    raise SystemExit(main())
