"""Tests for mocked incident response actions and chronological timeline tracking."""

from src.actions import (
    Timeline,
    isolate_host,
    open_ticket,
    page_on_call,
    post_incident_update,
    start_runbook_step,
    switch_runbook_step,
)
from src.models import ActionResult


def test_scripted_action_sequence_and_timeline() -> None:
    """Verify scripted action sequence executes, logs, and populates the timeline in order."""
    timeline = Timeline()
    inc_id = "inc-2024-test-actions"

    # 1. Isolate host
    res_isolate = isolate_host(
        asset="k8s-node-payments-prod-01", incident_id=inc_id, timeline=timeline
    )
    assert isinstance(res_isolate, ActionResult)
    assert res_isolate.action_type == "ISOLATE_HOST"
    assert res_isolate.status == "SUCCESS"

    # 2. Open ticket
    res_ticket = open_ticket(
        service="payments-api",
        summary="Critical CVE-2024-3094 remote code execution exposure",
        assignee="Alice Smith",
        incident_id=inc_id,
        timeline=timeline,
    )
    assert res_ticket.action_type == "OPEN_TICKET"
    assert "SEC-" in res_ticket.target

    # 3. Page on-call
    res_page = page_on_call(
        person="Alice Smith",
        service="payments-api",
        severity="CRITICAL",
        incident_id=inc_id,
        timeline=timeline,
    )
    assert res_page.action_type == "PAGE_ONCALL"
    assert res_page.target == "Alice Smith"

    # 4. Start runbook step
    res_step = start_runbook_step(
        incident_id=inc_id, step_name="Apply WAF Strict Ingress Drop", timeline=timeline
    )
    assert res_step.action_type == "START_RUNBOOK_STEP"

    # 5. Switch runbook step based on memory recall
    res_switch = switch_runbook_step(
        incident_id=inc_id,
        from_step="Apply WAF Strict Ingress Drop",
        to_step="VPC Security Group Egress Lockdown",
        reason="Past memory episode mem-ep-payments-01 showed WAF drop caused billing outage",
        timeline=timeline,
    )
    assert res_switch.action_type == "SWITCH_RUNBOOK_STEP"

    # 6. Post incident update
    res_update = post_incident_update(
        incident_id=inc_id,
        message="Host quarantined and egress lockdown active. Zero checkout drops.",
        timeline=timeline,
    )
    assert res_update.action_type == "POST_UPDATE"

    # Assert timeline ordering and serialization
    records = timeline.to_list()
    assert len(records) == 6

    expected_order = [
        "ISOLATE_HOST",
        "OPEN_TICKET",
        "PAGE_ONCALL",
        "START_RUNBOOK_STEP",
        "SWITCH_RUNBOOK_STEP",
        "POST_UPDATE",
    ]
    actual_order = [r["action_type"] for r in records]
    assert actual_order == expected_order

    # Assert fields on every timeline event
    for record in records:
        assert "action_type" in record
        assert "target" in record
        assert "status" in record
        assert record["status"] == "SUCCESS"
        assert "timestamp" in record
        assert "log_line" in record
        assert "details" in record
        assert len(record["log_line"]) > 10

    # Print timeline output for inspection
    print("\n--- SCRIPTED INCIDENT TIMELINE OUTPUT ---")
    for idx, r in enumerate(records, 1):
        print(f"{idx}. [{r['timestamp']}] {r['action_type']:<20} -> {r['target']:<24} | {r['log_line']}")
