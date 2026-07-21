from __future__ import annotations

import json

import pytest


def test_dashboard_ignores_malformed_audit_events(tmp_path, monkeypatch):
    pytest.importorskip("streamlit")
    from streamlit.testing.v1 import AppTest

    audit_path = tmp_path / "audit.jsonl"
    valid_event = {
        "timestamp": "2026-07-20T12:00:00+00:00",
        "command": "rmdir /s build",
        "risk_score": 0.98,
        "final_score": 0.98,
        "category": "DANGEROUS",
        "decision": "USER_CONFIRMATION",
        "executed": True,
        "intent_verification": {
            "intent_match_score": 1.0,
            "expected_action": "delete",
            "actual_action": "delete",
            "intent_decision": "ALLOW",
            "explanation": "The planned action matches the requested operation and target scope.",
        },
        "execution_preview": {
            "summary": "Delete action targeting build",
            "estimated_impact": "CRITICAL",
            "rollback": {"status": "READY", "rollback_id": "rb-demo", "instructions": ["Recovery copy created."]},
        },
    }
    audit_path.write_text("not json\n" + json.dumps(valid_event) + "\n" + "[]\n", encoding="utf-8")
    monkeypatch.setenv("SAFEAGENT_LOG", str(audit_path))
    monkeypatch.setenv("SAFEAGENT_CALIBRATION", str(tmp_path / "missing-calibration.csv"))
    monkeypatch.setenv("SAFEAGENT_MODEL_PATH", str(tmp_path / "missing-model.json"))
    monkeypatch.setenv("SAFEAGENT_TRAINING", str(tmp_path / "missing-training.csv"))

    app = AppTest.from_file("dashboard.py")
    app.run(timeout=30)
    assert not app.exception
    assert "Latest verification" in [item.value for item in app.header]
    assert len(app.metric) >= 4
