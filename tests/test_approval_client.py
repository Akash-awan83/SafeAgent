import json
import socket
import socketserver
import threading
from unittest.mock import patch

from safeagent.approval_console import ApprovalHandler, _show_request
from safeagent.mcp_server import ApprovalConsoleClient
from safeagent.models import RiskAssessment, RiskCategory


class ApprovalReplyHandler(socketserver.StreamRequestHandler):
    received: dict = {}

    def handle(self):
        ApprovalReplyHandler.received = json.loads(self.rfile.readline().decode("utf-8"))
        self.wfile.write(b'{"approved": true}\n')


def test_approval_client_sends_assessment_and_gets_human_response():
    with socketserver.TCPServer(("127.0.0.1", 0), ApprovalReplyHandler) as server:
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        client = ApprovalConsoleClient(host="127.0.0.1", port=server.server_address[1], timeout=1)
        assessment = RiskAssessment("rm -rf build", 0.98, RiskCategory.DANGEROUS)
        assert client(assessment, None) is True
        thread.join(timeout=1)
    assert ApprovalReplyHandler.received["command"] == "rm -rf build"
    assert ApprovalReplyHandler.received["category"] == "DANGEROUS"


def test_approval_console_accepts_explicit_yes():
    with patch("builtins.input", return_value="Y"):
        assert _show_request({"command": "rm -rf build", "risk_score": 0.98, "category": "DANGEROUS", "reasons": ["Recursive deletion"]}) is True


def test_approval_console_health_probe_does_not_request_input():
    with socketserver.TCPServer(("127.0.0.1", 0), ApprovalHandler) as server:
        thread = threading.Thread(target=server.handle_request, daemon=True)
        thread.start()
        with socket.create_connection(("127.0.0.1", server.server_address[1]), timeout=1) as connection:
            connection.sendall(b'{"type":"health"}\n')
            assert b'"status": "ok"' in connection.recv(128)
        thread.join(timeout=1)
