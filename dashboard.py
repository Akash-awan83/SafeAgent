"""SafeAgent security operations dashboard.

This file is intentionally presentation-only: it reads the existing audit log,
model metadata, and certification helpers without changing the safety gate.
"""
from __future__ import annotations

import csv
import io
import json
import math
import os
import socket
from datetime import datetime
from html import escape
from pathlib import Path
from typing import Any

import altair as alt
import streamlit as st

from safeagent.analytics import model_diagnostics
from safeagent.certification import certify_from_csv
from safeagent.dashboard_data import load_records, summary
from safeagent.risk_models import HybridRiskModel, MLRiskModel

LOG_PATH = os.getenv("SAFEAGENT_LOG", "data/decisions.jsonl")
CALIBRATION_PATH = os.getenv("SAFEAGENT_CALIBRATION", "data/calibration.csv")
MODEL_PATH = os.getenv("SAFEAGENT_MODEL_PATH", "models/logistic_risk_model.json")
TRAINING_PATH = os.getenv("SAFEAGENT_TRAINING", "data/training.csv")
RISK_ORDER = ["SAFE", "RISKY", "DANGEROUS"]
RISK_COLORS = ["#5ee0ae", "#f3c967", "#fb8497"]
ICONS = {
    "shield": "&#x25C6;",
    "intent": "&#x25CE;",
    "action": "&#x2192;",
    "risk": "!",
    "policy": "&#x2713;",
    "rollback": "&#x21BA;",
    "execute": "&#x25B6;",
    "blocked": "&#x00D7;",
    "audit": "&#x2261;",
    "empty": "&#x25CB;",
}
MATERIAL_ICONS = {
    "shield": "shield",
    "intent": "target",
    "execute": "play_circle",
    "blocked": "block",
}


def number(value: Any) -> float | None:
    """Return a finite score, keeping malformed audit fields out of charts."""
    try:
        parsed = float(value)
    except (TypeError, ValueError):
        return None
    return parsed if math.isfinite(parsed) else None


def timestamp(value: Any) -> str | None:
    if not isinstance(value, str) or not value.strip():
        return None
    try:
        datetime.fromisoformat(value.replace("Z", "+00:00"))
        return value
    except ValueError:
        return None


def text(value: Any, fallback: str = "-") -> str:
    return value.strip() if isinstance(value, str) and value.strip() else fallback


def intent_data(record: dict[str, Any]) -> dict[str, Any] | None:
    value = record.get("intent_verification")
    return value if isinstance(value, dict) else None


def preview_data(record: dict[str, Any]) -> dict[str, Any] | None:
    value = record.get("execution_preview")
    return value if isinstance(value, dict) else None


def intent_match(record: dict[str, Any]) -> float | None:
    verification = intent_data(record)
    return number(verification.get("intent_match_score")) if verification else None


def rollback_status(record: dict[str, Any]) -> str:
    preview = preview_data(record)
    rollback = preview.get("rollback") if preview else None
    return text(rollback.get("status"), "NOT RECORDED") if isinstance(rollback, dict) else "NOT RECORDED"


def safe_records() -> list[dict[str, Any]]:
    """Read only dictionary records; malformed JSONL lines are already skipped by the store."""
    try:
        return [record for record in load_records(LOG_PATH) if isinstance(record, dict)]
    except Exception:
        return []


def chart_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    valid: list[dict[str, Any]] = []
    for record in records:
        event_time = timestamp(record.get("timestamp"))
        risk = number(record.get("final_score"))
        if risk is None:
            risk = number(record.get("risk_score"))
        category = text(record.get("category"), "UNKNOWN").upper()
        if event_time is None or risk is None or category not in RISK_ORDER:
            continue
        valid.append({
            "timestamp": event_time,
            "command": text(record.get("command"), "Unknown command"),
            "risk_score": min(1.0, max(0.0, risk)),
            "category": category,
            "decision": text(record.get("decision"), "UNKNOWN"),
            "intent_match": intent_match(record),
        })
    return valid


def table_records(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return [{
        "Timestamp": text(record.get("timestamp")),
        "Command": text(record.get("command")),
        "Risk score": f"{(number(record.get('final_score')) if number(record.get('final_score')) is not None else number(record.get('risk_score')) or 0):.2f}",
        "Category": text(record.get("category"), "UNKNOWN").upper(),
        "Decision": text(record.get("decision"), "UNKNOWN"),
        "Intent match": "Unverified" if intent_match(record) is None else f"{intent_match(record) or 0:.0%}",
        "Rollback": rollback_status(record),
    } for record in records]


def approval_console_online() -> bool:
    try:
        with socket.create_connection((os.getenv("SAFEAGENT_APPROVAL_HOST", "127.0.0.1"), int(os.getenv("SAFEAGENT_APPROVAL_PORT", "8765"))), timeout=0.15) as connection:
            connection.sendall(b'{"type":"health"}\n')
            return b'"status": "ok"' in connection.recv(128)
    except OSError:
        return False


def safe_model() -> tuple[HybridRiskModel, bool]:
    try:
        if Path(MODEL_PATH).exists():
            return HybridRiskModel(ml_model=MLRiskModel.from_file(MODEL_PATH)), True
    except Exception:
        pass
    return HybridRiskModel(ml_model=MLRiskModel()), False


def safe_diagnostics() -> dict[str, Any] | None:
    try:
        return model_diagnostics(MODEL_PATH, TRAINING_PATH)
    except Exception:
        return None


def safe_certification(model: HybridRiskModel) -> Any | None:
    try:
        return certify_from_csv(CALIBRATION_PATH, model)
    except Exception:
        return None


def safe_output(value: Any) -> str:
    """Avoid presenting application tracebacks while retaining ordinary command output."""
    output = text(value, "")[:4000]
    suspicious_markers = ("traceback (most recent call last)", "schemavalidationerror", "exception:")
    if any(marker in output.lower() for marker in suspicious_markers):
        return "Command emitted an internal error. Detailed diagnostics remain in the local audit export."
    return output


def csv_export(records: list[dict[str, Any]]) -> str:
    rows = table_records(records)
    if not rows:
        return "Timestamp,Command,Risk score,Category,Decision\n"
    output = io.StringIO()
    writer = csv.DictWriter(output, fieldnames=list(rows[0]))
    writer.writeheader()
    writer.writerows(rows)
    return output.getvalue()


def show_chart(chart: alt.Chart, empty_message: str) -> None:
    try:
        st.altair_chart(chart, width="stretch")
    except Exception:
        st.info(empty_message)


def event_risk(event: dict[str, Any]) -> float:
    risk = number(event.get("final_score"))
    return risk if risk is not None else number(event.get("risk_score")) or 0.0


def event_intent(event: dict[str, Any]) -> str:
    verification = intent_data(event)
    if not verification:
        return "Intent context was not supplied"
    action = text(verification.get("expected_action"), "Unspecified")
    targets = verification.get("expected_targets")
    if isinstance(targets, list) and targets:
        return f"{action.capitalize()} {', '.join(text(target) for target in targets)}"
    return action.capitalize()


def event_rollback(event: dict[str, Any]) -> tuple[str, str]:
    preview = preview_data(event)
    rollback = preview.get("rollback") if preview else None
    if not isinstance(rollback, dict):
        return "NOT RECORDED", "No recovery information was recorded for this action."
    status = text(rollback.get("status"), "UNAVAILABLE")
    instructions = rollback.get("instructions")
    detail = " ".join(text(item) for item in instructions) if isinstance(instructions, list) else "Recovery status recorded by SafeAgent."
    return status, detail


def evidence(value: Any, fallback: str) -> tuple[str, ...]:
    if isinstance(value, list):
        values = tuple(text(item, "") for item in value if text(item, ""))
        if values:
            return values
    return (fallback,)


def event_intent_evidence(event: dict[str, Any]) -> tuple[str, ...]:
    verification = intent_data(event)
    if not verification:
        return ("Originating user intent was not supplied.",)
    return evidence(verification.get("evidence"), text(verification.get("explanation"), "No intent explanation was recorded."))


def event_risk_evidence(event: dict[str, Any]) -> tuple[str, ...]:
    return evidence(event.get("risk_factors"), text(event.get("reason"), "No risk explanation was recorded."))


def icon(name: str) -> str:
    """Return a static presentational mark without exposing icon markup in the UI."""
    return ICONS.get(name, ICONS["empty"])


def metric_card(column: Any, icon_name: str, label: str, value: str | int, detail: str) -> None:
    """Use native Streamlit metrics so values remain accessible and testable."""
    with column:
        with st.container(border=True):
            material_icon = MATERIAL_ICONS.get(icon_name, "insights")
            st.markdown(f":material/{material_icon}: **{label}**")
            st.metric(label, value, label_visibility="collapsed")
            st.caption(detail)


def workflow_step(icon_name: str, title: str, detail: str, tone: str = "success") -> None:
    st.markdown(
        f"<div class='workflow-step {tone}'><span class='workflow-icon'>{icon(icon_name)}</span>"
        f"<div><div class='workflow-title'>{escape(title)}</div><div class='workflow-detail'>{escape(detail)}</div></div></div>",
        unsafe_allow_html=True,
    )


def empty_state(title: str, detail: str) -> None:
    st.markdown(
        f"<div class='empty-state'><span class='empty-icon'>{icon('empty')}</span>"
        f"<div><div class='empty-title'>{escape(title)}</div><div class='empty-detail'>{escape(detail)}</div></div></div>",
        unsafe_allow_html=True,
    )


def verification_stage(title: str, value: str, detail: str, tone: str = "neutral") -> str:
    """Render one compact, escaped part of the primary verification story."""
    return (
        f"<div class='verification-stage {tone}'><div class='stage-title'>{escape(title)}</div>"
        f"<div class='stage-value'>{escape(value)}</div><div class='stage-detail'>{escape(detail)}</div></div>"
    )


def engine_node(icon_name: str, title: str, detail: str) -> str:
    return (
        f"<div class='engine-node'><span class='engine-icon'>{icon(icon_name)}</span>"
        f"<div><div class='engine-title'>{escape(title)}</div><div class='engine-status'>ACTIVE</div>"
        f"<div class='engine-detail'>{escape(detail)}</div></div></div>"
    )


def status_card(column: Any, label: str, state: str, detail: str, level: str) -> None:
    column.markdown(f"<div class='status-card'><div class='status-label'>{label}</div><span class='badge {level}'>{state}</span><div class='status-detail'>{detail}</div></div>", unsafe_allow_html=True)


st.set_page_config(page_title="SafeAgent | AI Action Verification", page_icon="\U0001f6e1\ufe0f", layout="wide", initial_sidebar_state="expanded")
st.markdown("""
<style>
  .stApp { background: #08111f; color: #eaf2fd; }
  [data-testid="stSidebar"] { background: #0c1728; border-right: 1px solid #263b58; }
  .block-container { max-width: 1440px; padding-top: 1.6rem; padding-bottom: 3rem; }
  .hero { display:flex; align-items:center; justify-content:space-between; gap:1rem; padding:1.45rem 1.65rem; margin-bottom:1.6rem; border:1px solid #2b4667; border-radius:18px; background:linear-gradient(120deg,#102640 0%,#0b1727 72%); }
  .hero-kicker, .section-kicker, .status-label { color:#91adce; font-size:.72rem; font-weight:750; letter-spacing:.11em; text-transform:uppercase; }
  .hero h1 { margin:.18rem 0 .22rem; color:#f6faff; font-size:2.18rem; letter-spacing:-.045em; }
  .hero p { margin:0; color:#b4c6da; font-size:1rem; }
  .protected-status { display:flex; align-items:center; gap:.5rem; color:#8df0c2; border:1px solid #255c4c; background:#102f2a; border-radius:999px; padding:.48rem .78rem; font-size:.8rem; font-weight:700; white-space:nowrap; }
  .protected-dot { width:.48rem; height:.48rem; border-radius:50%; background:#5ce1aa; box-shadow:0 0 0 4px rgba(92,225,170,.12); }
  .metric-card, .status-card { min-height:184px; border:1px solid #29425f; border-radius:14px; background:#0f1e31; padding:1.05rem 1.1rem; }
  .metric-top { display:flex; align-items:center; gap:.58rem; }.metric-icon { color:#8cc8ff; font-size:1.04rem; }
  .metric-label { color:#b7c8dd; font-size:.77rem; font-weight:700; letter-spacing:.07em; text-transform:uppercase; }
  .metric-value { color:#f7fbff; font-size:2.05rem; font-weight:760; letter-spacing:-.04em; margin:.68rem 0 .26rem; }
  .metric-detail, .status-detail { color:#91a8c4; font-size:.8rem; line-height:1.4; }
  .metric-signals { color:#aabed4; font-size:.76rem; line-height:1.55; list-style:none; padding:0; margin:.62rem 0 0; }.metric-signals li::before { content:'✓'; color:#5de0ac; padding-right:.4rem; font-weight:800; }
  .badge { display: inline-block; margin-top: .55rem; border-radius: 999px; padding: .24rem .58rem; font-size: .71rem; font-weight: 800; letter-spacing: .05em; }
  .online { background: #123d33; color: #79e6bf; } .warning { background: #493510; color: #ffd77c; } .offline { background: #49202b; color: #ffadba; }
  .workflow-heading { color:#91adce; font-size:.72rem; font-weight:750; letter-spacing:.11em; text-transform:uppercase; margin:1.2rem 0 .65rem; }
  .workflow-step { display:flex; gap:.75rem; align-items:flex-start; padding:.66rem 0 .66rem .2rem; border-left:1px solid #2e4b6e; }.workflow-icon { display:grid; place-items:center; width:1.7rem; height:1.7rem; margin-left:-.92rem; border:1px solid #315a80; border-radius:50%; background:#10263e; color:#88c8ff; font-size:.75rem; }.workflow-step.success .workflow-icon { border-color:#287359; color:#75e5b4; background:#102c29; }.workflow-step.warning .workflow-icon { border-color:#6a5223; color:#f0c86f; background:#302715; }.workflow-title { color:#e9f1fb; font-size:.88rem; font-weight:700; }.workflow-detail { color:#91a7c3; font-size:.79rem; margin-top:.1rem; }
  .empty-state { display:flex; gap:.85rem; align-items:center; padding:1.25rem .3rem; color:#aebfd3; }.empty-icon { color:#77b8ed; font-size:1.5rem; }.empty-title { color:#edf4fd; font-weight:700; margin-bottom:.18rem; }.empty-detail { font-size:.85rem; }
  h2, h3 { color:#edf4ff !important; letter-spacing:-.025em; margin-top:1.45rem !important; }
  [data-testid="stDataFrame"] { border:1px solid #29425f; border-radius:12px; overflow:hidden; }
  .block-container { max-width:1380px; padding-top:1.8rem; }
  .hero { gap:2rem; padding:1.65rem 1.8rem; margin-bottom:1.35rem; border-color:#294866; background:linear-gradient(118deg,#112b48 0%,#0b1828 76%); }
  .hero p { max-width:760px; font-size:.98rem; line-height:1.55; }.hero h1 { font-size:2.3rem; }
  .protected-status { border-radius:14px; padding:.62rem .82rem; }.protected-status strong { display:block; color:#9af3cb; font-size:.81rem; }.protected-status small { display:block; color:#88bca8; font-size:.7rem; margin-top:.08rem; }
  .metric-card { min-height:142px; padding:1rem 1.05rem; }.metric-icon { font-size:.9rem; }.metric-label { font-size:.72rem; }.metric-value { font-size:2rem; margin:.6rem 0 .25rem; }
  .verification-record { border:1px solid #294866; border-radius:16px; background:linear-gradient(145deg,#0d1e31,#0a1625); padding:1.15rem; }
  .request-card { height:100%; border:1px solid #213c59; border-radius:12px; background:#0c1929; padding:.9rem 1rem; }.request-card.action { border-color:#2d526e; }
  .request-label, .stage-title { color:#8fb4de; font-size:.68rem; font-weight:750; letter-spacing:.1em; text-transform:uppercase; }.request-value { color:#edf5ff; font-size:.93rem; font-weight:650; line-height:1.45; margin-top:.38rem; word-break:break-word; }
  .verification-rail { display:grid; grid-template-columns:repeat(5,minmax(0,1fr)); gap:.55rem; margin-top:.9rem; }.verification-stage { min-height:111px; border:1px solid #263f5c; border-radius:11px; background:#0b1928; padding:.78rem; }.verification-stage.success { border-color:#27634f; background:#0c2624; }.verification-stage.warning { border-color:#6b5527; background:#2a2212; }.stage-value { color:#f4f8fd; font-weight:750; font-size:1rem; line-height:1.25; margin:.55rem 0 .24rem; word-break:break-word; }.stage-detail { color:#98aec7; font-size:.73rem; line-height:1.35; }
  .engine-flow { display:flex; align-items:stretch; gap:.45rem; margin-top:.25rem; }.engine-node { flex:1; min-width:0; display:flex; gap:.62rem; border:1px solid #29425f; border-radius:12px; background:#0e1d2f; padding:.83rem; }.engine-node:not(:last-child)::after { content:'\\2192'; align-self:center; margin-right:-1.15rem; color:#6f9dcc; font-size:1rem; z-index:1; }.engine-icon { display:grid; place-items:center; flex:0 0 1.55rem; height:1.55rem; border:1px solid #27634f; border-radius:50%; background:#0d2d29; color:#7de7b8; font-size:.76rem; }.engine-title { color:#ebf3fc; font-size:.77rem; font-weight:750; line-height:1.25; }.engine-status { display:inline-block; margin-top:.3rem; color:#7de7b8; font-size:.61rem; font-weight:800; letter-spacing:.08em; }.engine-detail { color:#91a8c4; font-size:.71rem; line-height:1.35; margin-top:.36rem; }
  @media (max-width: 980px) { .hero { align-items:flex-start; flex-direction:column; gap:1rem; }.verification-rail { grid-template-columns:repeat(2,minmax(0,1fr)); }.engine-flow { flex-wrap:wrap; }.engine-node { flex-basis:30%; }.engine-node::after { display:none; } }
  @media (max-width: 640px) { .verification-rail { grid-template-columns:1fr; }.engine-node { flex-basis:100%; } }
</style>
""", unsafe_allow_html=True)
st.markdown("""
<div class='hero'><div><div class='hero-kicker'>AI action verification platform</div><h1>SafeAgent</h1><p>Before AI agents execute actions, SafeAgent verifies intent, evaluates risk, creates recovery paths, and ensures safe execution.</p></div><div class='protected-status'><span class='protected-dot'></span><div><strong>Protected</strong><small>Monitoring AI actions</small></div></div></div>
""", unsafe_allow_html=True)

with st.sidebar:
    st.markdown("### :material/filter_alt: Activity filters")
    search = st.text_input("Search commands", placeholder="rm, git push, curl…", key="command_search")
    st.caption("Audit data refreshes every five seconds.")


@st.fragment(run_every=5)
def render_dashboard() -> None:
    records = safe_records()
    if search:
        query = search.lower()
        records = [record for record in records if query in text(record.get("command"), "").lower()]

    available_categories = [category for category in RISK_ORDER if any(text(record.get("category"), "UNKNOWN").upper() == category for record in records)]
    selected_categories = st.multiselect("Risk category", available_categories, default=available_categories, placeholder="All categories")
    filtered = [record for record in records if not selected_categories or text(record.get("category"), "UNKNOWN").upper() in selected_categories]
    chart_data = chart_records(filtered)
    stats = summary(filtered)

    st.markdown("<div class='section-kicker'>Executive Overview</div>", unsafe_allow_html=True)
    st.header("AI action verification")
    awaiting = sum(record.get("user_response") in {None, "Pending"} and text(record.get("decision"), "") == "USER_CONFIRMATION" for record in filtered)
    verified = stats["intent_verified"]
    average_intent = stats["intent_match_percent"]
    risk_values = [event["risk_score"] for event in chart_data]
    average_safety = (1 - (sum(risk_values) / len(risk_values))) * 100 if risk_values else None
    trust_score = round(((average_intent * 0.65) + ((average_safety or 0) * 0.35))) if verified and average_safety is not None else None
    kpis = [
        ("shield", "System trust score", "Unavailable" if trust_score is None else f"{trust_score}%", "Based on historical verified actions and observed risk."),
        ("intent", "Average intent alignment", "Unverified" if not verified else f"{average_intent}%", "Across verified actions."),
        ("execute", "Protected actions", stats["executed"], "Actions completed through SafeAgent's verified execution path."),
        ("blocked", "Blocked risks", stats["cancelled"] + stats["blocked_errors"] + stats["blocked_policy"] + stats["intent_blocked"], "Stopped by policy, an intent guardrail, or a human decision."),
    ]
    for column, metric in zip(st.columns(4), kpis):
        metric_card(column, *metric)
    st.caption("System Trust Score is a historical aggregate, not a score for the latest command or a model-confidence claim.")
    st.caption(f"Approval queue: {awaiting} awaiting approval · {stats['user_approved'] + stats['cancelled']} recorded human decisions.")

    st.markdown("<div class='section-kicker'>Primary verification record</div>", unsafe_allow_html=True)
    st.header("Latest verification")
    with st.container(border=True):
        latest = filtered[-1] if filtered else None
        if latest is None:
            empty_state("No recent actions detected", "SafeAgent is monitoring AI operations. The next audited action will appear here with its verification evidence.")
        else:
            verification = intent_data(latest)
            preview = preview_data(latest)
            intent_score = intent_match(latest)
            rollback, rollback_detail = event_rollback(latest)
            decision = text(latest.get("decision"), "UNKNOWN")
            category = text(latest.get("category"), "UNKNOWN").upper()
            planned_action = text(preview.get("summary"), text(latest.get("command"), "Unknown command")) if preview else text(latest.get("command"), "Unknown command")
            request_column, action_column = st.columns(2, vertical_alignment="top")
            with request_column:
                st.markdown(
                    f"<div class='request-card'><div class='request-label'>User intent</div>"
                    f"<div class='request-value'>{escape(event_intent(latest))}</div></div>",
                    unsafe_allow_html=True,
                )
            with action_column:
                st.markdown(
                    f"<div class='request-card action'><div class='request-label'>AI planned action</div>"
                    f"<div class='request-value'>{escape(planned_action)}</div></div>",
                    unsafe_allow_html=True,
                )
            execution_state = "Completed" if bool(latest.get("executed")) else "Not executed"
            execution_detail = "SafeAgent recorded completion." if bool(latest.get("executed")) else "The action did not reach completion."
            intent_evidence = event_intent_evidence(latest)
            risk_evidence = event_risk_evidence(latest)
            st.markdown("<div class='workflow-heading'>Verification timeline</div>", unsafe_allow_html=True)
            st.caption(f"Recorded {text(latest.get('timestamp'), 'Timestamp unavailable')}")
            stages = "".join((
                verification_stage("Intent match", "Unverified" if intent_score is None else f"{intent_score:.0%}", intent_evidence[0], "success" if verification and text(verification.get("intent_decision")) == "ALLOW" else "warning"),
                verification_stage("Risk level", category.title(), f"Risk score {event_risk(latest):.2f}. {risk_evidence[0]}", "success" if category == "SAFE" else "warning"),
                verification_stage("Rollback status", rollback.replace("_", " ").title(), rollback_detail, "success" if rollback in {"AVAILABLE", "READY", "LIMITED"} else "warning"),
                verification_stage("Decision", decision.replace("_", " ").title(), "SafetyGate recorded the final policy outcome.", "success" if decision in {"AUTO_ALLOWED", "USER_CONFIRMATION"} else "warning"),
                verification_stage("Safe execution", execution_state, execution_detail, "success" if bool(latest.get("executed")) else "warning"),
            ))
            st.markdown(f"<div class='verification-rail'>{stages}</div>", unsafe_allow_html=True)
            intent_column, risk_column = st.columns(2)
            with intent_column:
                st.caption("Why this intent score")
                for item in intent_evidence:
                    st.markdown(f":green[✓] {item}")
            with risk_column:
                st.caption("Why this risk score")
                for item in risk_evidence:
                    st.markdown(f":green[✓] {item}")
    st.markdown("<div class='section-kicker'>How SafeAgent protects each action</div>", unsafe_allow_html=True)
    st.header("Safety engine")
    st.caption("Every proposed action follows this deterministic verification path before it can execute.")
    rollback_detail = f"{stats['rollback_ready']} action{'s' if stats['rollback_ready'] != 1 else ''} include recovery evidence." if stats["rollback_ready"] else "Creates recovery checkpoints before high-impact local actions."
    engine = "".join((
        engine_node("intent", "Intent verification", "Checks the requested action and its scope."),
        engine_node("risk", "Risk engine", "Scores risk with deterministic rules."),
        engine_node("policy", "Policy decision", "Allows, confirms, or blocks through SafetyGate."),
        engine_node("rollback", "Recovery protection", rollback_detail),
        engine_node("execute", "Safe execution", "Records the final outcome in the audit trail."),
    ))
    st.markdown(f"<div class='engine-flow'>{engine}</div>", unsafe_allow_html=True)

    with st.expander("Technical service health", expanded=False):
        st.caption("Live status for integration and research-supporting services.")
        model, model_loaded = safe_model()
        diagnostic = safe_diagnostics() if model_loaded else None
        certificate = safe_certification(model)
        approval_online = approval_console_online()
        mcp_column, approval_column, model_column, certification_column = st.columns(4)
        status_card(mcp_column, "MCP Status", "WARNING", "Session-managed by Codex. Confirm availability with /mcp.", "warning")
        status_card(approval_column, "Approval Console", "ONLINE" if approval_online else "OFFLINE", "Ready for human prompts." if approval_online else "Start safeagent.approval_console before risky commands.", "online" if approval_online else "offline")
        validation = diagnostic.get("metadata", {}).get("validation_metrics", {}) if diagnostic else {}
        detail = f"Validation F1: {float(validation.get('f1', 0)):.2f}" if validation else "Rule-based safety remains active."
        status_card(model_column, "Model Status", "ONLINE" if model_loaded else "WARNING", detail, "online" if model_loaded else "warning")
        if certificate:
            state = "ONLINE" if certificate.certified else "WARNING"
            detail = f"{1-certificate.delta:.0%} confidence; upper bound {certificate.upper_confidence_bound:.2%}."
            status_card(certification_column, "Certification", state, detail, "online" if certificate.certified else "warning")
        else:
            status_card(certification_column, "Certification", "OFFLINE", "Calibration data is unavailable.", "offline")
    st.markdown("<div class='section-kicker'>Operational evidence</div>", unsafe_allow_html=True)
    st.header("Risk and decision history")
    timeline_column, distribution_column, decision_column = st.columns([2, 1, 1])
    with timeline_column:
        st.subheader("Execution timeline")
        if chart_data:
            chart = alt.Chart(alt.Data(values=chart_data)).mark_circle(size=70, opacity=.85).encode(
                x=alt.X("timestamp:T", title="Timestamp"),
                y=alt.Y("risk_score:Q", title="Risk score", scale=alt.Scale(domain=[0, 1])),
                color=alt.Color("category:N", scale=alt.Scale(domain=RISK_ORDER, range=RISK_COLORS), title="Category"),
                tooltip=[alt.Tooltip("timestamp:T", title="Timestamp"), alt.Tooltip("command:N", title="Command"), alt.Tooltip("risk_score:Q", title="Risk score", format=".2f"), alt.Tooltip("decision:N", title="Decision")],
            ).properties(height=290).interactive()
            show_chart(chart, "No valid risk timeline data available")
        else:
            empty_state("No recent actions detected", "SafeAgent is monitoring AI operations. Execution evidence will appear after the first audit event.")
    with distribution_column:
        st.subheader("Risk distribution")
        bins = [{"category": category, "count": sum(event["category"] == category for event in chart_data)} for category in RISK_ORDER]
        if any(item["count"] for item in bins):
            chart = alt.Chart(alt.Data(values=bins)).mark_bar(cornerRadiusTopLeft=4, cornerRadiusTopRight=4).encode(x=alt.X("category:N", title=None, sort=RISK_ORDER), y=alt.Y("count:Q", title="Commands"), color=alt.Color("category:N", scale=alt.Scale(domain=RISK_ORDER, range=RISK_COLORS), legend=None), tooltip=["category:N", "count:Q"]).properties(height=290)
            show_chart(chart, "No valid risk distribution data available")
        else:
            empty_state("No risk data yet", "Risk distribution appears after audited actions are recorded.")
    with decision_column:
        st.subheader("Safety policy decisions")
        decisions: dict[str, int] = {}
        for record in filtered:
            label = text(record.get("decision"), "UNKNOWN")
            decisions[label] = decisions.get(label, 0) + 1
        decision_data = [{"decision": name, "count": count} for name, count in decisions.items() if count > 0]
        if decision_data:
            chart = alt.Chart(alt.Data(values=decision_data)).mark_arc(innerRadius=42).encode(theta=alt.Theta("count:Q"), color=alt.Color("decision:N", title="Decision"), tooltip=["decision:N", "count:Q"]).properties(height=290)
            show_chart(chart, "No valid decision data available")
        else:
            empty_state("No decisions recorded", "Safety outcomes will appear here when SafeAgent evaluates actions.")

    st.markdown("<div class='section-kicker'>Recent Activity</div>", unsafe_allow_html=True)
    st.header("Latest audited commands")
    rows = table_records(list(reversed(filtered[-20:])))
    activity_rows = [{key: row[key] for key in ("Timestamp", "Command", "Risk score", "Category", "Decision")} for row in rows]
    if rows:
        st.dataframe(activity_rows, width="stretch", height=365, hide_index=True, column_config={"Command": st.column_config.TextColumn(width="large")})
    else:
        empty_state("No recent actions detected", "SafeAgent is monitoring AI operations. Adjust filters or execute an action through the gateway.")
    high_risk = [record for record in reversed(filtered) if text(record.get("category"), "UNKNOWN").upper() in {"RISKY", "DANGEROUS"}]
    with st.container(border=True):
        st.subheader("Recent high-risk commands")
        if high_risk:
            risk_rows = table_records(high_risk[:10])
            st.dataframe([{key: row[key] for key in ("Timestamp", "Command", "Risk score", "Category", "Decision")} for row in risk_rows], hide_index=True, column_config={"Command": st.column_config.TextColumn(width="large")})
        else:
            st.caption("No risky or dangerous commands are present in the selected activity.")

    st.markdown("<div class='section-kicker'>Audit Explorer</div>", unsafe_allow_html=True)
    st.header("Selected command")
    if filtered:
        positions = list(range(len(filtered)))
        selected = st.selectbox("Choose an audit event", positions, format_func=lambda index: f"{text(filtered[-1-index].get('timestamp'))} | {text(filtered[-1-index].get('command'))}")
        event = filtered[-1-selected]
        detail_column, output_column = st.columns(2)
        with detail_column:
            st.caption("Command")
            st.code(text(event.get("command"), "Unknown command"), language=None)
            final_risk = number(event.get("final_score"))
            if final_risk is None:
                final_risk = number(event.get("risk_score"))
            st.metric("Final risk score", f"{(final_risk or 0):.2f}")
            st.write(f"**Category:** {text(event.get('category'), 'UNKNOWN').upper()}")
            st.write(f"**Decision:** {text(event.get('decision'), 'UNKNOWN')}")
            st.write(f"**Reason:** {text(event.get('reason'), 'No explanation recorded.')}")
            rules = event.get("rule_detections")
            if isinstance(rules, list) and rules:
                st.caption("Detected safety rules")
                st.write(", ".join(text(rule.get("id"), "Unnamed rule") for rule in rules if isinstance(rule, dict)))
            verification = intent_data(event)
            if verification:
                st.subheader("Intent verification")
                match_score = number(verification.get("intent_match_score"))
                st.write(f"**Match:** {'Unverified' if match_score is None else f'{match_score:.0%}'}")
                st.write(f"**Expected action:** {text(verification.get('expected_action'))}")
                st.write(f"**Actual action:** {text(verification.get('actual_action'))}")
                st.write(f"**Intent decision:** {text(verification.get('intent_decision'))}")
                st.caption(text(verification.get("explanation"), "No intent explanation recorded."))
        with output_column:
            st.subheader("Execution preview")
            preview = preview_data(event)
            if preview:
                st.write(f"**Planned impact:** {text(preview.get('estimated_impact'), 'UNKNOWN')}")
                st.write(text(preview.get("summary"), "No action summary recorded."))
                for label, key in (("Files", "files_affected"), ("Directories", "directories_affected"), ("Git", "git_operations"), ("Network", "network_access"), ("Sensitive paths", "secret_access")):
                    values = preview.get(key)
                    if isinstance(values, list) and values:
                        st.write(f"**{label}:** {', '.join(text(value) for value in values)}")
                rollback = preview.get("rollback")
                if isinstance(rollback, dict):
                    st.write(f"**Rollback status:** {text(rollback.get('status'), 'UNAVAILABLE')}")
                    rollback_id = text(rollback.get("rollback_id"), "")
                    if rollback_id:
                        st.write(f"**Rollback ID:** {rollback_id}")
                    instructions = rollback.get("instructions")
                    if isinstance(instructions, list) and instructions:
                        st.caption(" ".join(text(item) for item in instructions))
            else:
                st.caption("Execution preview was not recorded for this older audit event.")
            st.subheader("Execution summary")
            st.write(f"**Approved by human:** {text(event.get('user_response'), 'Not required')}")
            st.write(f"**Approval time:** {number(event.get('approval_time_ms')) or 0:.0f} ms")
            st.write(f"**Execution time:** {number(event.get('execution_time_ms')) or 0:.0f} ms")
            output = safe_output(event.get("stdout"))
            error_output = safe_output(event.get("stderr"))
            if output or error_output:
                with st.expander("Command output"):
                    if output:
                        st.code(output, language=None)
                    if error_output:
                        st.code(error_output, language=None)
            else:
                st.caption("No command output recorded.")
    else:
        with st.container(border=True):
            empty_state("No action evidence available", "SafeAgent is monitoring AI operations. Select an audited event once one is recorded.")

    st.download_button("Download filtered audit JSON", data=json.dumps(filtered, indent=2, default=str), file_name="safeagent-audit.json", mime="application/json")
    st.download_button("Export filtered audit CSV", data=csv_export(filtered), file_name="safeagent-audit.csv", mime="text/csv")


render_dashboard()
st.caption("SafeAgent is HC-RLHF-inspired: rule-based detection, optional ML risk prediction, and held-out certification. It is not full Seldonian optimization.")
