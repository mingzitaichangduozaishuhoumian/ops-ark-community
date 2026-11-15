"""Contrast actual website reachability with unavailable SSH after first-use readback."""

import argparse
import hashlib
import importlib.util
import json
import re
import subprocess
import sys
import time
from pathlib import Path

SPEC = importlib.util.spec_from_file_location(
    "onboarding_owned_lab", Path(__file__).with_name("onboarding_lab.py")
)
assert SPEC is not None and SPEC.loader is not None
owned = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(owned)
require = owned.require
RESTART = """import os,stat,subprocess,sys
from pathlib import Path
for entry in Path('/proc').iterdir():
    if not entry.name.isdigit(): continue
    try: executable=(entry/'exe').resolve(strict=True)
    except (FileNotFoundError,ProcessLookupError): continue
    assert executable not in (Path('/usr/sbin/sshd'),Path('/usr/sbin/nginx'))
for name in ('/run/opsark-onboarding/upstream.json',
             '/run/opsark-onboarding/nginx.pid','/run/sshd.pid'):
    path=Path(name)
    if path.exists() or path.is_symlink():
        info=path.lstat()
        assert stat.S_ISREG(info.st_mode) and info.st_uid==0 and info.st_nlink==1
        path.unlink()
subprocess.run([sys.executable,'-I','-B','/run/opsark-onboarding/target.py','start'],check=True,
               stdin=subprocess.DEVNULL,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
print('restored')
"""
STOP = """import os,select,signal,socket,sys
from pathlib import Path
kind=sys.argv[1]
assert kind in ('ssh','web')
binary=Path('/usr/sbin/sshd' if kind=='ssh' else '/usr/sbin/nginx')
config=b'/run/opsark-onboarding/'+(b'sshd.conf' if kind=='ssh' else b'nginx.conf')
address='198.18.242.2' if kind=='ssh' else '0.0.0.0'
port=22 if kind=='ssh' else 8080
endpoint=socket.inet_aton(address)[::-1].hex().upper()+f':{port:04X}'
def listeners():
    return [parts for line in Path('/proc/net/tcp').read_text().splitlines()[1:]
            if (parts:=line.split())[3]=='0A' and parts[1]==endpoint]
rows=listeners(); assert len(rows)==1
socket_link='socket:['+rows[0][9]+']'
candidates=[]
for entry in Path('/proc').iterdir():
    if not entry.name.isdigit(): continue
    try:
        if (entry/'exe').resolve(strict=True)!=binary.resolve(strict=True): continue
        command=(entry/'cmdline').read_bytes()
        if config not in command: continue
        found=False
        for fd in (entry/'fd').iterdir():
            try: found=found or os.readlink(fd)==socket_link
            except FileNotFoundError: pass
        if found:
            started=(entry/'stat').read_text().rsplit(') ',1)[1].split()[19]
            candidates.append((entry,command,started))
    except (FileNotFoundError,ProcessLookupError): continue
assert len(candidates)==1
entry,command,start=candidates[0]; pid=int(entry.name)
descriptor=os.pidfd_open(pid,0)
try:
    for name in ('net','mnt','pid'):
        assert os.path.samestat((entry/'ns'/name).stat(),Path('/proc/self/ns',name).stat())
    assert (entry/'exe').resolve()==binary.resolve() and (entry/'cmdline').read_bytes()==command
    assert (entry/'stat').read_text().rsplit(') ',1)[1].split()[19]==start
    signal.pidfd_send_signal(descriptor,signal.SIGTERM)
    assert select.select([descriptor],[],[],3)[0]
finally: os.close(descriptor)
assert not listeners()
print('stopped')
"""
API = """import base64,http.client,json,sys
from contextlib import closing
from pathlib import Path
method,path,payload=sys.argv[1:]
token=Path('/app/data/access-token').read_text(encoding='ascii').strip()
headers={'Authorization':'Bearer '+token}
if payload: headers['Content-Type']='application/json'
with closing(http.client.HTTPConnection('127.0.0.1',8010,timeout=12)) as c:
    c.request(method,path,payload or None,headers)
    r=c.getresponse(); body=r.read(262145)
    assert len(body)<=262144
    print(json.dumps([r.status,r.getheader('Cache-Control'),base64.b64encode(body).decode('ascii')]))
"""
HTTP = """import http.client,json,socket
from contextlib import closing
def fetch(host):
    try:
        with closing(http.client.HTTPConnection('198.18.242.2',8080,timeout=1)) as c:
            c.request('GET','/healthz',headers={'Host':host})
            response=c.getresponse(); body=response.read(2049)
            assert len(body)<=2048
            return [response.status,body.decode('ascii')]
    except ConnectionRefusedError: return ['refused',None]
print(json.dumps([fetch('shop.opsark.invalid'),fetch('blog.opsark.invalid')]))
"""


def report_hash(report):
    return hashlib.sha256(
        json.dumps(report, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode(
            "utf-8"
        )
    ).hexdigest()


def private_json(root, path):
    require(
        path.parent == root and path.resolve() == path,
        "The first-use proof must be a direct private stage child",
    )
    value = json.loads(owned.private_read(path))
    require(isinstance(value, dict), "Invalid private first-use proof")
    return value


class Contrast:
    def __init__(self, lab, record, proof):
        self.lab = lab
        self.record = private_json(lab.root, record)
        passed = private_json(lab.root, proof)
        require(
            set(self.record)
            == {"host_id", "report_id", "scope_hash", "report_sha256", "summary_sha256"}
            and self.record["host_id"] == owned.HOST
            and isinstance(self.record["report_id"], str)
            and re.fullmatch(r"[A-Za-z0-9_-]{1,80}", self.record["report_id"])
            and all(
                isinstance(self.record[field], str)
                and re.fullmatch(r"[0-9a-f]{64}", self.record[field])
                for field in ("scope_hash", "report_sha256", "summary_sha256")
            ),
            "The original first-use record is invalid",
        )
        require(
            set(passed)
            == {
                "report_survived_restart",
                "customer_summary_bytes_identical",
                "real_backend_without_browser_mocks",
                "unexpected_writes_absent",
            }
            and all(value is True for value in passed.values()),
            "The original browser readback must pass before the access contrast",
        )
        self.seen = {self.record["report_id"]}

    def api(self, method, path, payload=None):
        import base64

        result = json.loads(
            self.lab.execute(
                "controller",
                owned.PYTHON,
                "-I",
                "-B",
                "-c",
                API,
                method,
                path,
                "" if payload is None else json.dumps(payload),
            )
        )
        require(
            isinstance(result, list) and len(result) == 3 and result[1] == "no-store",
            "Invalid protected controller response",
        )
        return result[0], base64.b64decode(result[2], validate=True)

    def json_api(self, method, path, payload=None, *, code=200):
        status, raw = self.api(method, path, payload)
        require(status == code, "The protected controller response status differs")
        return json.loads(raw)

    def original(self):
        path = "/api/reports/" + self.record["report_id"]
        report = self.json_api("GET", path)
        require(
            report["scope_hash"] == self.record["scope_hash"]
            and report_hash(report) == self.record["report_sha256"],
            "The original first-use report changed",
        )
        status, summary = self.api("GET", path + "/handoff")
        require(
            status == 200 and hashlib.sha256(summary).hexdigest() == self.record["summary_sha256"],
            "The original first-use export changed",
        )

    def baseline(self):
        target = self.lab.resource("target")["Id"]
        self.lab.docker("restart", "-t", "5", target)
        require(
            self.lab.execute("target", "/usr/bin/python3", "-I", "-B", "-c", RESTART)
            == b"restored",
            "The exact owned target did not restore its native baseline",
        )
        self.http(good=True)

    def http(self, *, good):
        result = json.loads(self.lab.execute("controller", owned.PYTHON, "-I", "-B", "-c", HTTP))
        expected = [
            [200, "OPSARK_ONBOARDING_UPSTREAM_OK\n"],
            [200, "OPSARK_ONBOARDING_CONTROL_OK\n"],
        ]
        require(
            result == (expected if good else [["refused", None], ["refused", None]]),
            "The independent website observation did not match the controlled listener state",
        )

    def stop(self, kind):
        require(
            self.lab.execute("target", "/usr/bin/python3", "-I", "-B", "-c", STOP, kind)
            == b"stopped",
            "The exact owned listener did not stop",
        )

    def investigate(self, *, access_failed):
        report = self.json_api(
            "POST",
            "/api/investigations",
            {
                "source": "ssh",
                "scenario": "web_502",
                "host_id": owned.HOST,
            },
        )
        require(
            report["id"] not in self.seen
            and report["source"] == "ssh"
            and report["host_id"] == owned.HOST
            and report["scope_hash"] == self.record["scope_hash"]
            and report["action"]["executable"] is False
            and report["comparison"]["restore_capable"] is False
            and report["ai"]["status"] == "not_requested"
            and all(item["status"] != "passed" for item in report["verification"]),
            "The new investigation lost its source, identity or action boundary",
        )
        self.seen.add(report["id"])
        if access_failed:
            evidence = report["evidence"]
            require(
                report["status"] == "inconclusive"
                and len(evidence) == 1
                and evidence[0]["check_id"] == "connection"
                and evidence[0]["source"] == "ssh"
                and evidence[0]["status"] == "error"
                and evidence[0]["exit_code"] is None
                and not report["facts"]
                and not report["candidates"],
                "Unavailable SSH was converted into application or historical conclusions",
            )
            self.json_api(
                "POST",
                "/api/reports/" + report["id"] + "/baseline",
                {"confirm_observation_only": True},
                code=409,
            )
        else:
            checks = {item["check_id"]: item for item in report["evidence"]}
            require(
                "connection" not in checks
                and checks["os_release"]["status"] == "ok"
                and "ID=ubuntu" in checks["os_release"]["output"],
                "Native SSH collection did not return after restoring the target",
            )

    def run(self):
        started = time.monotonic()
        require(
            self.lab.state and self.lab.state["phase"] == "faulted",
            "Complete the first-use fault and browser readback before this extra case",
        )
        self.original()
        prior = self.json_api("GET", "/api/reports")
        require(1 <= len(prior) <= 20, "The first-use report scope is outside this bounded fixture")
        retained = {
            row["id"]: report_hash(self.json_api("GET", "/api/reports/" + row["id"]))
            for row in prior
        }
        self.seen.update(retained)
        state_before = owned.private_read(self.lab.state_path)
        inventory_before = owned.private_read(self.lab.cfg / "inventory.toml", uid=owned.UID)
        known_before = owned.private_read(self.lab.cfg / owned.KNOWN, uid=owned.UID)
        baselines_before = self.json_api("GET", "/api/baselines")
        restored = False
        try:
            self.baseline()
            self.stop("ssh")
            self.http(good=True)
            self.investigate(access_failed=True)
            self.stop("web")
            self.http(good=False)
            self.investigate(access_failed=True)
            self.baseline()
            restored = True
            self.lab.guard_check()
            self.investigate(access_failed=False)
            self.original()
            require(
                all(
                    report_hash(self.json_api("GET", "/api/reports/" + report_id)) == digest
                    for report_id, digest in retained.items()
                ),
                "A previously stored first-use report changed",
            )
            require(
                self.json_api("GET", "/api/baselines") == baselines_before,
                "Incomplete SSH collection created an observation baseline",
            )
            require(
                owned.private_read(self.lab.state_path) == state_before
                and owned.private_read(self.lab.cfg / "inventory.toml", uid=owned.UID)
                == inventory_before
                and owned.private_read(self.lab.cfg / owned.KNOWN, uid=owned.UID) == known_before,
                "The access contrast changed original fixture enrollment",
            )
        finally:
            if not restored:
                self.baseline()
        elapsed = time.monotonic() - started
        require(elapsed <= 150, "The bounded access contrast exceeded its acceptance budget")
        return {
            "case": "D-ACCESS-01",
            "partial_case_coverage": True,
            "registered_business_checks_verified": False,
            "website_healthy_with_ssh_unavailable": True,
            "website_refused_with_ssh_unavailable": True,
            "both_reports_inconclusive": True,
            "restored_native_ssh_verified": True,
            "original_first_use_artifacts_unchanged": True,
            "incomplete_observation_baseline_rejected": True,
            "fresh_ssh_reports": 3,
            "prior_reports_preserved": len(retained),
            "elapsed_seconds": round(elapsed, 2),
            "subprocess_calls_timeout_bounded": True,
        }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", type=Path, required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--controller-image", required=True)
    parser.add_argument("--first-use-record", type=Path, required=True)
    parser.add_argument("--readback-proof", type=Path, required=True)
    parser.add_argument("--confirm-isolated", action="store_true", required=True)
    args = parser.parse_args()
    try:
        lab = owned.Lab(args.root)
        require(
            lab.state
            and lab.state["image"] == args.image
            and lab.state["controller_image"] == args.controller_image,
            "The recorded isolated image scope differs",
        )
        proof = Contrast(lab, args.first_use_record, args.readback_proof).run()
        print(json.dumps(proof, sort_keys=True))
    except RuntimeError as error:
        print(str(error), file=sys.stderr)
        return 1
    except (OSError, ValueError, TypeError, KeyError, IndexError, subprocess.SubprocessError):
        print("The isolated access contrast could not complete", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
