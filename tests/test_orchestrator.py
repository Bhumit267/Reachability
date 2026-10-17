"""Integration and unit tests for the multi-agent incident orchestrator."""

import subprocess
import sys
import pytest

from src.models import IncidentRun
from src.orchestrator import run_incident
from src.queries import get_incident, get_incident_actions


def test_run_incident_lifecycle() -> None:
    """Verify that run_incident creates an incident, attaches actions, writes memory, and marks it contained."""
    service = "payments-api"
    cve = "CVE-2024-3094"

    run = run_incident(service=service, cve=cve)

    assert isinstance(run, IncidentRun)
    assert run.incident_id.startswith("inc-")
    assert run.service == service
    assert run.cve == cve

    # Step 1 & 6: Verify incident node exists and is contained
    inc_record = get_incident(run.incident_id)
    assert inc_record is not None
    assert inc_record["status"] == "contained"
    assert inc_record["service_id"] == service
    assert inc_record["cve"] == cve

    # Step 2 & 3: Blast radius and code impact results
    assert run.blast_radius is not None
    assert len(run.blast_radius.answer) > 0
    assert run.code_impact is not None
    assert len(run.code_impact.answer) > 0

    # Step 4 & 5: Confirm 4+ actions attached to Incident in graph
    actions_in_graph = get_incident_actions(run.incident_id)
    assert len(actions_in_graph) >= 4

    action_types = [a["type"] for a in actions_in_graph]
    assert "ISOLATE_HOST" in action_types
    assert "OPEN_TICKET" in action_types
    assert "PAGE_ONCALL" in action_types

    # Timeline in order
    assert len(run.timeline) >= 4
    timestamps = [e["timestamp"] for e in run.timeline]
    assert timestamps == sorted(timestamps)

    # Memory episode written
    assert run.memory_written is not None
    assert run.memory_written.startswith("mem-")

    # Graph paths cited
    assert len(run.all_graph_paths) >= 1


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
