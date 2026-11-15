#!/usr/bin/python3 -I
"""Bridge only the container restart role's exact command to its fixed root helper."""

import os
import sys

COMMAND = "opsark-container-restart-v1"
ROOT_ACTION = "/usr/local/lib/opsark-container-restart/restart_action.py"


def main():
    if (
        len(sys.argv) != 1
        or os.environ.get("SSH_ORIGINAL_COMMAND") != COMMAND
        or sys.stdin.isatty()
    ):
        return 126
    os.execve(  # noqa: S606 - only this exact argv is granted by the deployment role.
        "/usr/bin/sudo",
        ["/usr/bin/sudo", "-n", "--", "/usr/bin/python3", "-I", "-B", ROOT_ACTION],
        {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    return 126


if __name__ == "__main__":
    raise SystemExit(main())
