#!/usr/bin/python3 -I
"""Accept one fixed SSH command and bridge stdin to the installed root action."""

import os
import sys

COMMAND = "opsark-nginx-action-v1"
ROOT_ACTION = "/usr/local/lib/opsark-nginx-action/deploy/nginx/managed_action.py"


def main() -> int:
    if (
        len(sys.argv) != 1
        or os.environ.get("SSH_ORIGINAL_COMMAND") != COMMAND
        or sys.stdin.isatty()
    ):
        sys.stderr.write("Nginx action entry refused.\n")
        return 126
    os.execve(  # noqa: S606 -- installed sudoers grants only these exact fixed arguments.
        "/usr/bin/sudo",
        ["/usr/bin/sudo", "-n", "--", "/usr/bin/python3", "-I", "-B", ROOT_ACTION],
        {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C"},
    )
    return 126


if __name__ == "__main__":
    raise SystemExit(main())
