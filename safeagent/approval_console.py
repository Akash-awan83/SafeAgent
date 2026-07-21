"""A separate terminal UI for approvals requested by the stdio MCP server.

MCP owns the server's stdin/stdout, so prompting there would corrupt the protocol.
This localhost-only bridge keeps human confirmation independent of the AI process.
"""
from __future__ import annotations

import argparse
import json
import socketserver
from typing import Any


def _show_request(request: dict[str, Any]) -> bool:
    print("\n[SafeAgent] Confirmation required", flush=True)
    print(f"Command: {request['command']}")
    print(f"Risk score: {request['risk_score']:.2f} ({request['category']})")
    print("Reason:")
    for reason in request.get("reasons", []):
        print(f"- {reason}")
    intent = request.get("intent_verification")
    if isinstance(intent, dict):
        print("\nIntent verification:")
        score = intent.get("intent_match_score")
        score_text = "Unverified" if score is None else f"{float(score):.0%} match"
        print(f"- Status: {intent.get('intent_decision', 'UNVERIFIED')} ({score_text})")
        print(f"- Expected: {intent.get('expected_action', 'Unknown')}")
        print(f"- Actual: {intent.get('actual_action', 'Unknown')}")
        print(f"- {intent.get('explanation', 'No explanation recorded.')}")
    preview = request.get("execution_preview")
    if isinstance(preview, dict):
        print("\nExecution preview:")
        print(f"- {preview.get('summary', 'Command execution')}")
        print(f"- Estimated impact: {preview.get('estimated_impact', 'UNKNOWN')}")
        for label, key in (("Files", "files_affected"), ("Directories", "directories_affected"), ("Git", "git_operations"), ("Network", "network_access"), ("Sensitive paths", "secret_access")):
            values = preview.get(key)
            if isinstance(values, list) and values:
                print(f"- {label}: {', '.join(str(value) for value in values)}")
        rollback = preview.get("rollback")
        if isinstance(rollback, dict):
            print(f"- Rollback: {rollback.get('status', 'UNAVAILABLE')}")
            for instruction in rollback.get("instructions", []):
                print(f"  {instruction}")
    advisory = request.get("advisory")
    if advisory:
        print(f"AI-generated advisory: {advisory.get('explanation', '')}")
        if advisory.get("safer_alternative"):
            print(f"Safer alternative: {advisory['safer_alternative']}")
    return input("Execute anyway? [Y] Yes [N] Cancel: ").strip().lower() in {"y", "yes"}


class ApprovalHandler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        try:
            request = json.loads(self.rfile.readline().decode("utf-8"))
            if request.get("type") == "health":
                self.wfile.write(b'{"status": "ok"}\n')
                return
            approved = _show_request(request)
            self.wfile.write(json.dumps({"approved": approved}).encode("utf-8") + b"\n")
        except Exception:
            self.wfile.write(b'{"approved": false, "error": "approval console failure"}\n')


class ApprovalServer(socketserver.ThreadingTCPServer):
    allow_reuse_address = True


def main() -> int:
    parser = argparse.ArgumentParser(description="SafeAgent human approval console")
    parser.add_argument("--host", default="127.0.0.1")
    parser.add_argument("--port", type=int, default=8765)
    args = parser.parse_args()
    with ApprovalServer((args.host, args.port), ApprovalHandler) as server:
        print(f"SafeAgent approval console listening on {args.host}:{args.port}", flush=True)
        server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
