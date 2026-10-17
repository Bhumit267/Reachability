"""Integration, regression, and failure prevention tests for the incident orchestrator."""

import subprocess
import sys
from typing import Any, Dict, List, Optional
from unittest.mock import MagicMock

import pytest

from src.agents.code_impact_agent import CodeImpactAgent
from src.agents.commander import CommanderAgent
from src.agents.security_agent import SecurityAgent
from src.models import AgentResult, CommanderResult, GraphPath, IncidentRun
from src.orchestrator import run_incident
from src.queries import get_incident, get_incident_actions


def test_successful_containment() -> None:
    """Verify that a normal run satisfies all containment criteria and is marked contained."""
    service = "payments-api"
    cve = "CVE-2024-3094"

    run = run_incident(service=service, cve=cve)

    assert isinstance(run, IncidentRun)
    assert run.status == "contained"
    assert run.incident_id.startswith("inc-")
    assert run.service == service
    assert run.cve == cve

    # Graph record is contained
    inc_record = get_incident(run.incident_id)
    assert inc_record is not None
    assert inc_record["status"] == "contained"

    # Actions executed and attached
    actions_in_graph = get_incident_actions(run.incident_id)
    assert len(actions_in_graph) >= 4
    assert len(run.timeline) >= 4
    assert run.memory_written is not None


def test_security_agent_failure_prevents_containment() -> None:
    """Verify that if security analysis fails or lacks a graph path, actions are aborted and status is failed."""
    service = "payments-api"
    cve = "CVE-2024-3094"

    mock_sec = MagicMock(spec=SecurityAgent)
    mock_sec.analyze.return_value = AgentResult(
        success=False,
        answer="Security agent failed to identify valid attack paths.",
        graph_path=None,
        tool_calls=[],
        raw={"error": "MOCK_FAILURE"},
    )
    mock_cmd = MagicMock(spec=CommanderAgent)

    run = run_incident(service=service, cve=cve, security_agent=mock_sec, commander_agent=mock_cmd)

    assert run.status == "failed"
    inc_record = get_incident(run.incident_id)
    assert inc_record is not None
    assert inc_record["status"] == "failed"

    # Precondition failed: Commander must NOT have been called, no actions executed
    mock_cmd.command.assert_not_called()
    assert len(run.timeline) == 0
    actions_in_graph = get_incident_actions(run.incident_id)
    assert len(actions_in_graph) == 0


def test_code_impact_failure_prevents_containment() -> None:
    """Verify that if code-impact analysis fails or lacks a graph path, actions are aborted and status is failed."""
    service = "payments-api"
    cve = "CVE-2024-3094"

    mock_impact = MagicMock(spec=CodeImpactAgent)
    mock_impact.analyze.return_value = AgentResult(
        success=False,
        answer="Code-impact agent failed to trace repository ownership.",
        graph_path=None,
        tool_calls=[],
        raw={"error": "MOCK_IMPACT_FAILURE"},
    )
    mock_cmd = MagicMock(spec=CommanderAgent)

    run = run_incident(service=service, cve=cve, code_impact_agent=mock_impact, commander_agent=mock_cmd)

    assert run.status == "failed"
    inc_record = get_incident(run.incident_id)
    assert inc_record is not None
    assert inc_record["status"] == "failed"

    # Precondition failed: Commander must NOT have been called, no actions executed
    mock_cmd.command.assert_not_called()
    assert len(run.timeline) == 0
    actions_in_graph = get_incident_actions(run.incident_id)
    assert len(actions_in_graph) == 0


def test_commander_failure_prevents_containment() -> None:
    """Verify that if the commander reports failure, the incident is marked failed rather than contained."""
    service = "payments-api"
    cve = "CVE-2024-3094"

    mock_cmd = MagicMock(spec=CommanderAgent)
    mock_cmd.command.return_value = CommanderResult(
        incident_id="inc-test-fail",
        service=service,
        cve=cve,
        summary="Commander aborted due to conflicting or missing assets.",
        action_timeline=[],
        graph_paths=[],
        memory_influence="Aborted",
        episode_id=None,
        success=False,
    )

    run = run_incident(service=service, cve=cve, commander_agent=mock_cmd)

    assert run.status == "failed"
    inc_record = get_incident(run.incident_id)
    assert inc_record is not None
    assert inc_record["status"] == "failed"


def test_exception_during_response_prevents_containment() -> None:
    """Verify that exceptions during agent analysis or commander execution do not mark the incident contained."""
    service = "payments-api"
    cve = "CVE-2024-3094"

    # Case A: Security agent raises exception
    mock_sec_exc = MagicMock(spec=SecurityAgent)
    mock_sec_exc.analyze.side_effect = RuntimeError("FalkorDB connection timeout during reachability check")

    run_a = run_incident(service=service, cve=cve, security_agent=mock_sec_exc)
    assert run_a.status == "failed"
    assert get_incident(run_a.incident_id)["status"] == "failed"
    assert "FalkorDB connection timeout" in run_a.blast_radius.answer

    # Case B: Commander raises exception
    mock_cmd_exc = MagicMock(spec=CommanderAgent)
    mock_cmd_exc.command.side_effect = ConnectionResetError("API gateway connection dropped during action dispatch")

    run_b = run_incident(service=service, cve=cve, commander_agent=mock_cmd_exc)
    assert run_b.status == "failed"
    assert get_incident(run_b.incident_id)["status"] == "failed"
    assert "API gateway connection dropped" in run_b.commander_result.summary


def test_orchestrator_cli_execution() -> None:
    """Execute the orchestrator CLI module and confirm structured output format."""
    cmd = [sys.executable, "-m", "src.orchestrator", "payments-api", "CVE-2024-3094"]
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)

    assert result.returncode == 0
    out = result.stdout

    assert "CVE COMMANDER -- INCIDENT RUN REPORT:" in out
    assert "Target Service   : payments-api" in out
    assert "Final Status     : CONTAINED" in out
    assert "BLAST RADIUS ANALYSIS" in out
    assert "CODE IMPACT & OWNERSHIP" in out
    assert "COMMANDER DECISION & MEMORY INFLUENCE" in out
    assert "CHRONOLOGICAL ACTION TIMELINE:" in out
    assert "ISOLATE_HOST" in out
    assert "OPEN_TICKET" in out
    assert "PAGE_ONCALL" in out
    assert "VERIFIED GRAPH PATHS CITED:" in out
