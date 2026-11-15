"""Check a downloaded activation bundle offline; never contact a target or a model."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))

from opsark.activation_evidence import main  # noqa: E402 -- repository-local read-only entry.

if __name__ == "__main__":
    raise SystemExit(main())
