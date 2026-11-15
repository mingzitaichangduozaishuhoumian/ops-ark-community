"""Fixed acceptance-only business collector transport on loopback TCP 22422.

The management container, image, network, mounts and lifetime are verified by
the same closed validator as the independent defense relay.  Its byte pump,
budgets, EOF handling and cleanup are reused unchanged.  This class offers no
choice of destination: management .4 can reach only target .2:22422.

No credentials are loaded, no production client is patched, and no remote
host port is published. The collector still verifies the enrolled host pin.
"""

import inspect
import shlex
import socket
import threading
import time
from dataclasses import asdict

import defense_native_relay as native

ADDRESS = ("127.0.0.1", 22422)
RelayScope = native.RelayScope
RelayRefused = native.RelayRefused

# The already-reviewed inner program has exactly two destination literals:
# connect() and its peer verification. Refuse an unexpected dependency change
# instead of applying a broad textual adaptation to unknown source.
if native.PROXY_SOURCE.count("22423") != 2:
    raise RelayRefused()
PROXY_SOURCE = native.PROXY_SOURCE.replace("22423", "22422")


def remote_command(scope: RelayScope) -> str:
    """Use the unchanged scope inspector and a different fixed inner port."""
    if type(scope) is not RelayScope:
        raise RelayRefused()
    scope = RelayScope(**asdict(scope))
    source = (
        "S="
        + repr(asdict(scope))
        + "\nPROXY="
        + repr(PROXY_SOURCE)
        + "\n"
        + inspect.getsource(native._require)
        + "\n"
        + inspect.getsource(native._verify_inspections)
        + "\n"
        + native.INSPECTOR_SOURCE
    )
    return shlex.join(
        ("/usr/bin/timeout", "-k", "1s", "36s", "/usr/bin/python3", "-I", "-u", "-c", source)
    )


class FixedBusinessRelay(native.FixedDefenseRelay):
    """Independent fixed listener; inherited forwarding has the same limits."""

    def __init__(self, scope: RelayScope, open_channel):
        super().__init__(scope, open_channel)
        self.command = remote_command(scope)

    def __enter__(self):
        # Keep this lifecycle aligned with the existing relay. Only the fixed
        # listen address and diagnostic thread name differ.
        if self._started:
            raise RelayRefused()
        self._started = True
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            if hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
                listener.setsockopt(socket.SOL_SOCKET, socket.SO_EXCLUSIVEADDRUSE, 1)
            listener.bind(ADDRESS)
            listener.listen(native.MAX_CONCURRENT)
            listener.settimeout(0.1)
        except OSError:
            listener.close()
            self._stopped.set()
            raise RelayRefused() from None
        self._listener, self._deadline = listener, time.monotonic() + native.LIFETIME_SECONDS
        self._acceptor = threading.Thread(
            target=self._accept, name="opsark-fixed-business-relay", daemon=True
        )
        try:
            self._acceptor.start()
        except RuntimeError:
            listener.close()
            self._listener = self._acceptor = None
            self._stopped.set()
            raise RelayRefused() from None
        return self


__all__ = ["FixedBusinessRelay", "RelayRefused", "RelayScope"]
