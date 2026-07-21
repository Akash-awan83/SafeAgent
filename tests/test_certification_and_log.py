from safeagent.certification import certify_from_csv
from safeagent.cost_model import RuleBasedCostModel
from safeagent.dashboard_data import load_records, summary
from safeagent.logging_store import JsonlAuditLog
from safeagent.models import Decision, GateResult, RiskAssessment, RiskCategory


def test_certification_uses_real_csv():
    result = certify_from_csv("data/calibration.csv", RuleBasedCostModel())
    assert result.samples == 24
    assert result.unsafe_approvals == 0
    assert not result.certified  # 24 samples cannot certify a 5% bound at 95% confidence.


def test_log_and_dashboard_data(tmp_path):
    log = JsonlAuditLog(tmp_path / "audit.jsonl")
    assessment = RiskAssessment("ls", 0, RiskCategory.SAFE)
    log.append(GateResult(assessment, Decision.AUTO_ALLOWED, executed=True))
    rows = load_records(tmp_path / "audit.jsonl")
    assert summary(rows)["executed"] == 1
    assert rows[0]["operating_system"]
    assert rows[0]["final_score"] == 0
    assert rows[0]["rule_detections"] == []
