"""Run inside the isolated CI container, without printing its access token."""

import errno
import json
import os
import stat
import time
from pathlib import Path
from urllib.error import HTTPError
from urllib.request import Request, urlopen


def run() -> None:
    data_dir = Path(os.environ.get("OPSARK_DATA_DIR", "/app/data"))
    token = (data_dir / "access-token").read_text(encoding="utf-8").strip()
    base = "http://127.0.0.1:8010"

    def request(path: str, payload: dict | None = None) -> dict | list | str:
        headers = {"Authorization": "Bearer " + token}
        body = None if payload is None else json.dumps(payload).encode()
        if body is not None:
            headers["Content-Type"] = "application/json"
        call = Request(base + path, data=body, headers=headers)  # noqa: S310 -- fixed loopback base.
        with urlopen(call, timeout=10) as response:  # noqa: S310 -- fixed loopback URL.
            content = response.read().decode("utf-8")
        return content if path.endswith("/export") else json.loads(content)

    if os.getuid() != 10001:
        raise RuntimeError("The application must run as its non-root image user")
    if stat.S_IMODE(data_dir.stat().st_mode) != 0o700:
        raise RuntimeError("Evidence and token directory must remain private to its owner")
    if stat.S_IMODE((data_dir / "access-token").stat().st_mode) != 0o600:
        raise RuntimeError("Access token must not be group- or world-readable")
    probe = Path("/app/ci-readonly-probe")
    try:
        probe.write_text("read-only filesystem check", encoding="utf-8")
    except OSError as error:
        if error.errno not in {errno.EROFS, errno.EACCES}:
            raise
    else:
        probe.unlink()
        raise RuntimeError("The container application directory must not be writable")
    for attempt in range(20):
        try:
            with urlopen(base + "/api/status", timeout=2) as response:  # noqa: S310
                if response.status == 200:
                    break
        except OSError:
            if attempt == 19:
                raise
            time.sleep(0.5)
    marker = data_dir / "ci-smoke-report-id"
    if os.environ.get("OPSARK_SMOKE_STAGE") == "verify":
        report_id = marker.read_text(encoding="utf-8")
        report = request("/api/reports/" + report_id)
        if not isinstance(report, dict) or report["action"]["executable"]:
            raise RuntimeError("Persisted read-only report did not survive restart")
        print("Container persistence check passed; no real SSH or model requests were made.")
        return
    samples = request("/api/samples")
    if not isinstance(samples, list) or len(samples) != 12:
        raise RuntimeError("Expected the documented replay sample set")
    report = request(
        "/api/investigations",
        {
            "source": "replay",
            "scenario": "web_502",
            "sample_id": "web-port-mismatch",
        },
    )
    if (
        not isinstance(report, dict)
        or report["source"] != "replay"
        or report["action"]["executable"]
    ):
        raise RuntimeError("Unexpected replay report boundary")
    marker.write_text(report["id"], encoding="utf-8")
    exported = request("/api/reports/" + report["id"] + "/export")
    if not isinstance(exported, str) or "虚构数据" not in exported:
        raise RuntimeError("Export lost its data provenance")
    try:
        with urlopen(base + "/api/reports", timeout=5):  # noqa: S310 -- fixed loopback URL.
            raise RuntimeError("Unauthenticated report access must be refused")
    except HTTPError as error:
        if error.code != 401:
            raise
    print("Container API check passed; token remained private and actions stayed disabled.")


if __name__ == "__main__":
    run()
