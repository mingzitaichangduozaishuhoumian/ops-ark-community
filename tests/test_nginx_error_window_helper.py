"""Test the target's bounded projection without reading a real Nginx log."""

import errno
import json
from datetime import UTC, datetime

import pytest

from deploy.readonly import nginx_error_window as helper

NOW = 1783008000
TARGET = "target.invalid"
REFUSED = b"connect() failed (111: Connection refused) while connecting to upstream"
TIMEOUT = (
    b"upstream timed out (110: Connection timed out) while reading response header from upstream"
)


def row(age, kind=REFUSED, server=TARGET):
    stamp = datetime.fromtimestamp(NOW - age, UTC).strftime("%Y/%m/%d %H:%M:%S").encode()
    context = (
        f', client: 127.0.0.1, server: {server}, request: "GET /probe HTTP/1.1", '
        'upstream: "http://127.0.0.1:18081/probe", host: "target.invalid"'
    ).encode()
    return stamp + b" [error] 123#123: *45 " + kind + context + b"\n"


def test_observes_two_upstream_classes_and_includes_window_boundaries():
    data = row(901) + row(900) + row(901 - 900, server="other.invalid") + row(0, TIMEOUT)
    assert helper.project(data, TARGET, NOW) == {"refused": 1, "timeout": 1}


def test_covered_no_relevant_is_distinct_from_incomplete_or_empty():
    assert helper.project(row(901) + row(10, server="other.invalid"), TARGET, NOW) == {
        "refused": 0,
        "timeout": 0,
    }
    for data in (b"", row(900), row(10, server="other.invalid")):
        with pytest.raises(helper.Refused, match="coverage_unconfirmed"):
            helper.project(data, TARGET, NOW)


@pytest.mark.parametrize(
    "suffix",
    (
        row(0).rstrip(b"\n"),
        row(-1),
        row(10) + row(11),
        b"malformed record\n",
        row(0).replace(b"server: target.invalid, request:", b"server: target.invalid, invalid:"),
        row(0).replace(b"127.0.0.1, server:", b"dead, server:"),
        row(0).replace(b"[error]", b"[unknown]"),
        row(0).replace(b"request: ", b"request: \x00"),
        row(0).replace(b"/probe", b"x" * helper.MAX_LINE),
        row(0) * helper.MAX_ROWS,
        row(0).replace(b"/probe", b"x" * helper.MAX_BYTES),
    ),
    ids=(
        "partial",
        "future",
        "order",
        "malformed",
        "ambiguous",
        "bad_ip",
        "level",
        "control",
        "line_limit",
        "row_limit",
        "byte_limit",
    ),
)
def test_incomplete_or_ambiguous_input_cannot_claim_counts(suffix):
    with pytest.raises(helper.Refused, match="coverage_unconfirmed"):
        helper.project(row(901) + suffix, TARGET, NOW)


def test_nonrelevant_event_can_contain_keyword_in_request_without_attribution():
    log = row(
        0, kind=b"connect() failed (101: Network is unreachable) while connecting to upstream"
    )
    log = log.replace(b"GET /probe", b"GET /Connection refused")
    assert helper.project(row(901) + log, TARGET, NOW) == {"refused": 0, "timeout": 0}


@pytest.mark.parametrize(
    ("failure", "status", "reason"),
    (
        (PermissionError(errno.EACCES, "private"), "permission_denied", None),
        (helper.Missing("private"), "source_missing", None),
        (helper.Refused("source_changed"), "inconclusive", "source_changed"),
        (OSError(errno.EIO, "private"), "inconclusive", "read_unconfirmed"),
    ),
)
def test_collection_classifies_filesystem_result_without_raw_data(
    monkeypatch, failure, status, reason
):
    def bad(*_args):
        raise failure

    monkeypatch.setattr(helper, "read_regular", bad)
    assert helper.collect(TARGET, NOW, NOW, 0) == (status, reason, None, None)


def test_collection_rejects_timezone_or_source_change(monkeypatch):
    monkeypatch.setattr(helper, "read_regular", lambda *_args: (row(901) + row(0), ("file",)))
    zones = iter(("first", "changed"))
    monkeypatch.setattr(helper, "utc_profile", lambda: next(zones))
    assert helper.collect(TARGET, NOW, NOW, 0) == ("inconclusive", "clock_unconfirmed", None, None)
    monkeypatch.setattr(helper, "utc_profile", lambda: "constant")

    def changed(_expected):
        raise helper.Refused("source_changed")

    monkeypatch.setattr(helper, "check_current_log", changed)
    assert helper.collect(TARGET, NOW, NOW, 0) == ("inconclusive", "source_changed", None, None)


def test_current_source_rejects_changed_trusted_parent_even_with_same_file(monkeypatch):
    from contextlib import contextmanager
    from types import SimpleNamespace

    @contextmanager
    def replacement_parent(_path):
        yield 1, lambda: None, ("different-parent",)

    original_stat = SimpleNamespace(
        st_dev=1,
        st_ino=2,
        st_mode=0o100644,
        st_uid=0,
        st_gid=0,
        st_nlink=1,
        st_size=10,
        st_ctime_ns=1,
        st_mtime_ns=1,
    )
    monkeypatch.setattr(helper, "parent_chain", replacement_parent)
    monkeypatch.setattr(helper.os, "stat", lambda *_args, **_kwargs: original_stat)
    with pytest.raises(helper.Refused, match="source_changed"):
        helper.check_current_log((helper.identity(original_stat), ("old-parent",)))


def test_main_emits_one_closed_line_only(monkeypatch, capsys):
    monkeypatch.setattr(helper.sys, "platform", "linux")
    monkeypatch.setattr(helper.signal, "SIGALRM", 14, raising=False)
    monkeypatch.setattr(helper.signal, "alarm", lambda *_args: None, raising=False)
    monkeypatch.setattr(helper.signal, "signal", lambda *_args: None)
    monkeypatch.setattr(helper, "drop_privileges", lambda: None)
    received = []

    def collect(expected, *_args):
        received.append(expected)
        return "observed", None, 1, 0

    monkeypatch.setattr(helper, "collect", collect)
    assert helper.main([TARGET, "/some/path"]) == 2
    assert helper.main(["not_a_domain.invalid"]) == 2
    assert capsys.readouterr().out == ""
    assert helper.main([TARGET.upper()]) == 0 and received == [TARGET]
    captured = capsys.readouterr()
    assert captured.err == "" and len(captured.out.splitlines()) == 1
    result = json.loads(captured.out)
    assert set(result) == {
        "schema",
        "status",
        "reason",
        "observed_at",
        "window_seconds",
        "matching_refused",
        "matching_timeout",
    }
    assert result["schema"] == helper.SCHEMA and result["window_seconds"] == 900
    assert result["observed_at"].endswith("Z") and TARGET not in captured.out
