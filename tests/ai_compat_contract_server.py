"""Loopback protocol fixture, explicitly NOT a model or an inference substitute."""

import json
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

MODEL = "opsark-contract-test-no-inference"
KEY = "contract-only-not-a-real-api-key"


class Handler(BaseHTTPRequestHandler):
    def log_message(self, _format, *_args):
        pass

    def do_POST(self):
        if (
            self.path != "/v1/chat/completions"
            or self.headers.get("Authorization") != "Bearer " + KEY
        ):
            self.send_error(404)
            return
        size = int(self.headers.get("Content-Length", "0"))
        if not 0 < size <= 65_536:
            self.send_error(413)
            return
        try:
            request = json.loads(self.rfile.read(size))
            assert request["model"] == MODEL
            reduced = json.loads(request["messages"][-1]["content"])
            serialized = json.dumps(reduced)
            assert all(
                item not in serialized
                for item in (
                    "host_id",
                    "scan_id",
                    "policy_digest",
                    "172.29.",
                    "198.51.100.22",
                    "192.0.2.87",
                    "/root/",
                    "/etc/",
                    "api_key",
                )
            )
            candidate = next(c for c in reduced["candidate_catalog"] if c["eligible"] is True)
            finding = next(
                f for f in reduced["findings"] if f["finding_ref"] == candidate["finding_ref"]
            )
            evidence = finding["evidence_ref"]
            result = {
                "summary": "受控实验的官方包证据确认受影响，协议测试选择现有候选供核验。",
                "uncertainty": ["协议测试不执行模型推理，部分供应商覆盖仍有缺口。"],
                "evidence_refs": [evidence, "coverage-1"],
                "finding_analyses": [
                    {
                        "finding_ref": finding["finding_ref"],
                        "priority": "planned",
                        "reason_codes": ["vendor_confirmed_affected", "candidate_available"],
                        "rationale": "官方版本与候选证据相符，需生成原生事务核验。",
                        "evidence_refs": [evidence],
                    }
                ],
                "proposals": [
                    {
                        "candidate_id": candidate["candidate_id"],
                        "rationale": "协议测试只选择目录中的单包候选，不执行任何安装。",
                        "evidence_refs": [evidence],
                    }
                ],
                "actions_executable": False,
            }
            response = json.dumps(
                {
                    "model": MODEL,
                    "choices": [
                        {
                            "finish_reason": "stop",
                            "message": {"role": "assistant", "content": json.dumps(result)},
                        }
                    ],
                }
            ).encode()
            print(
                json.dumps(
                    {
                        "contract_test_only": True,
                        "request_received": True,
                        "model": MODEL,
                        "identity_fields_received": False,
                    }
                ),
                flush=True,
            )
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(response)))
            self.end_headers()
            self.wfile.write(response)
        except (ValueError, KeyError, TypeError, StopIteration, AssertionError):
            self.send_error(422)


if __name__ == "__main__":
    ThreadingHTTPServer(("127.0.0.1", 19111), Handler).serve_forever()
