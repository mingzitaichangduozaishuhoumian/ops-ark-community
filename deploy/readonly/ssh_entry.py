#!/usr/bin/python3 -I
"""Only bridge OpenSSH's original command into the exact root guard argument."""

import os
import sys

GUARD = "/usr/local/libexec/opsark-readonly-guard"


def main():
    command = os.environ.get("SSH_ORIGINAL_COMMAND", "")
    if len(sys.argv) != 1 or not command or len(command.encode("utf-8")) > 4096:
        sys.stderr.write("OpsArk requires an approved collection command.\n")
        return 126
    os.execve(  # noqa: S606 -- fixed sudo executable; original command remains one argument.
        "/usr/bin/sudo",
        ["/usr/bin/sudo", "-n", "--", GUARD, command],
        {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin", "LC_ALL": "C", "HOME": "/nonexistent"},
    )
    return 126


if __name__ == "__main__":
    raise SystemExit(main())
