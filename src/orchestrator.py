"""Incident response orchestrator coordinating specialized agents, actions, and graph state."""

import sys
import uuid
from typing import Any, Dict, List, Optional

from src.actions import Timeline
from src.agents.code_impact_agent import CodeImpactAgent
from src.agents.commander import CommanderAgent
from src.agents.security_agent import SecurityAgent
from src.models import GraphPath, IncidentRun
from src.queries import attach_incident_action, close_incident, create_incident


def run_incident(
    service: str,
    cve: str,
    security_agent: Optional[SecurityAgent] = None,
    code_impact_agent: Optional[CodeImpactAgent] = None,
    commander_agent: Optional[CommanderAgent] = None,
) -> IncidentRun:
    """Coordinate the end-to-end multi-agent response for a critical service CVE."""
    incident_id = f"inc-{uuid.uuid4().hex[:8]}"

    # Step 1: Create Incident node in graph with status = 'open'
    create_incident(incident_id=incident_id, service_name=service, cve=cve)

    # Step 2: Run security blast-radius agent
    sec_agent = security_agent or SecurityAgent()
    blast_radius = sec_agent.analyze(service=service, cve=cve)

    # Step 3: Run code-impact agent
    imp_agent = code_impact_agent or CodeImpactAgent()
    code_impact = imp_agent.analyze(service=service, cve=cve)

    # Step 4: Run commander agent (executes mitigation actions and writes memory)
    timeline = Timeline()
    cmd_agent = commander_agent or CommanderAgent()
    commander_result = cmd_agent.command(
        incident_id=incident_id,
        service=service,
        cve=cve,
        timeline=timeline,
    )

    # Step 5: Attach all Action nodes to the Incident
    for event in timeline.actions:
        action_id = event.details.get("action_id")
        if action_id:
            attach_incident_action(incident_id=incident_id, action_id=action_id)

    # Step 6: Close incident with status = 'contained'
    close_incident(incident_id=incident_id, status="contained")

    # Step 7: Assemble and return IncidentRun
    all_paths: List[GraphPath] = []
    seen_readable = set()

    for path in (
        ([blast_radius.graph_path] if blast_radius.graph_path else [])
        + ([code_impact.graph_path] if code_impact.graph_path else [])
        + commander_result.graph_paths
    ):
        if path.readable not in seen_readable:
            seen_readable.add(path.readable)
            all_paths.append(path)

    return IncidentRun(
        incident_id=incident_id,
        service=service,
        cve=cve,
        blast_radius=blast_radius,
        code_impact=code_impact,
        commander_result=commander_result,
        timeline=timeline.to_list(),
        memory_written=commander_result.episode_id,
        all_graph_paths=all_paths,
    )


def print_incident_summary(run: IncidentRun) -> None:
    """Print a structured, human-readable terminal summary of the incident run."""
    print("=" * 80)
    print(f"  CVE COMMANDER -- INCIDENT RUN REPORT: {run.incident_id}")
    print("=" * 80)
    print(f"Target Service   : {run.service}")
    print(f"Target CVE       : {run.cve}")
    print(f"Final Status     : CONTAINED")
    print(f"Memory Written   : {run.memory_written or 'None'}")
    print("-" * 80)

    print("\n[1] BLAST RADIUS ANALYSIS (Security Agent):")
    print(f"    {run.blast_radius.answer}")
    if run.blast_radius.graph_path:
        print(f"    Attack Path  : {run.blast_radius.graph_path.readable}")

    print("\n[2] CODE IMPACT & OWNERSHIP (Code Impact Agent):")
    print(f"    {run.code_impact.answer}")
    if run.code_impact.graph_path:
        print(f"    Code Path    : {run.code_impact.graph_path.readable}")

    print("\n[3] COMMANDER DECISION & MEMORY INFLUENCE:")
    print(f"    Summary      : {run.commander_result.summary}")
    print(f"    Memory Alert : {run.commander_result.memory_influence}")

    print("\n[4] CHRONOLOGICAL ACTION TIMELINE:")
    for idx, act in enumerate(run.timeline, 1):
        ts = act.get("timestamp", "")[:19].replace("T", " ")
        action_type = act.get("action_type", "ACTION")
        target = act.get("target", "")
        log_line = act.get("log_line", "")
        status = act.get("status", "SUCCESS")
        print(f"    {idx}. [{ts}] {action_type:<18} -> {target:<20} [{status}]")
        print(f"       Log: {log_line}")

    print("\n[5] VERIFIED GRAPH PATHS CITED:")
    for idx, path in enumerate(run.all_graph_paths, 1):
        print(f"    {idx}. {path.readable}")

    print("=" * 80)
    print(f"Incident {run.incident_id} successfully mitigated and contained.")
    print("=" * 80)


if __name__ == "__main__":
    target_service = sys.argv[1] if len(sys.argv) > 1 else "payments-api"
    target_cve = sys.argv[2] if len(sys.argv) > 2 else "CVE-2024-3094"

    print(f"\n[+] Initiating autonomous incident response for {target_service} ({target_cve})...\n")
    incident_run = run_incident(service=target_service, cve=target_cve)
    print_incident_summary(incident_run)
