"""Incident response orchestrator coordinating specialized agents, actions, and graph state."""

import sys
import uuid
from typing import Any, Dict, List, Optional

from src.actions import Timeline
from src.agents.code_impact_agent import CodeImpactAgent
from src.agents.commander import CommanderAgent
from src.agents.security_agent import SecurityAgent
from src.models import AgentResult, CommanderResult, GraphPath, IncidentRun
from src.queries import attach_incident_action, close_incident, create_incident, get_cves_for_service


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

    # Validate that the selected CVE affects an asset hosting this service
    applicable_cves = get_cves_for_service(service)
    if applicable_cves and cve not in applicable_cves:
        close_incident(incident_id=incident_id, status="failed")
        err_msg = f"Validation Error: {cve} is not present on any asset running '{service}'."
        err_res = AgentResult(success=False, answer=err_msg, graph_path=None, tool_calls=[], raw={"error": "CVE_SERVICE_MISMATCH"})
        cmd_err = CommanderResult(incident_id=incident_id, service=service, cve=cve, summary=err_msg, action_timeline=[], graph_paths=[], memory_influence="None", episode_id=None, success=False)
        return IncidentRun(
            incident_id=incident_id, service=service, cve=cve, blast_radius=err_res, code_impact=err_res, commander_result=cmd_err, timeline=[], status="failed", memory_written=None, all_graph_paths=[]
        )

    # Step 2: Run security blast-radius agent (with exception handling)
    try:
        sec_agent = security_agent or SecurityAgent()
        blast_radius = sec_agent.analyze(service=service, cve=cve)
    except Exception as exc:
        blast_radius = AgentResult(success=False, answer=f"Security agent error: {exc}", graph_path=None, tool_calls=[], raw={"error": str(exc)})

    # Precondition check: Security analysis must succeed and provide a verified graph path
    if not blast_radius.success or blast_radius.graph_path is None:
        close_incident(incident_id=incident_id, status="failed")
        err_msg = f"Investigation Failed: Security analysis failed or lacks graph path ({blast_radius.answer}). Response actions aborted."
        code_skipped = AgentResult(success=False, answer="Code-impact analysis skipped due to security analysis failure.", graph_path=None, tool_calls=[], raw={"skipped": True})
        cmd_aborted = CommanderResult(incident_id=incident_id, service=service, cve=cve, summary=err_msg, action_timeline=[], graph_paths=[], memory_influence="Aborted", episode_id=None, success=False)
        return IncidentRun(
            incident_id=incident_id, service=service, cve=cve, blast_radius=blast_radius, code_impact=code_skipped, commander_result=cmd_aborted, timeline=[], status="failed", memory_written=None, all_graph_paths=[]
        )

    # Step 3: Run code-impact agent (with exception handling)
    try:
        imp_agent = code_impact_agent or CodeImpactAgent()
        code_impact = imp_agent.analyze(service=service, cve=cve)
    except Exception as exc:
        code_impact = AgentResult(success=False, answer=f"Code-impact agent error: {exc}", graph_path=None, tool_calls=[], raw={"error": str(exc)})

    # Precondition check: Code-impact analysis must succeed and provide a verified graph path
    if not code_impact.success or code_impact.graph_path is None:
        close_incident(incident_id=incident_id, status="failed")
        err_msg = f"Investigation Failed: Code-impact analysis failed or lacks graph path ({code_impact.answer}). Response actions aborted."
        cmd_aborted = CommanderResult(incident_id=incident_id, service=service, cve=cve, summary=err_msg, action_timeline=[], graph_paths=[blast_radius.graph_path], memory_influence="Aborted", episode_id=None, success=False)
        return IncidentRun(
            incident_id=incident_id, service=service, cve=cve, blast_radius=blast_radius, code_impact=code_impact, commander_result=cmd_aborted, timeline=[], status="failed", memory_written=None, all_graph_paths=[blast_radius.graph_path]
        )

    # Step 4: Run commander agent (mandatory preconditions met: both security & code-impact verified)
    timeline = Timeline()
    cmd_agent = commander_agent or CommanderAgent()
    try:
        commander_result = cmd_agent.command(
            incident_id=incident_id,
            service=service,
            cve=cve,
            timeline=timeline,
        )
    except Exception as exc:
        commander_result = CommanderResult(
            incident_id=incident_id,
            service=service,
            cve=cve,
            summary=f"Commander execution exception: {exc}",
            action_timeline=timeline.to_list(),
            graph_paths=[],
            memory_influence="Error during execution",
            episode_id=None,
            success=False,
        )

    # Step 5: Attach all Action nodes to the Incident
    for event in timeline.actions:
        action_id = event.details.get("action_id")
        if action_id:
            attach_incident_action(incident_id=incident_id, action_id=action_id)

    # Step 6: Close incident with appropriate status based on strict containment criteria
    is_contained = bool(
        blast_radius.success
        and blast_radius.graph_path is not None
        and code_impact.success
        and code_impact.graph_path is not None
        and commander_result.success
        and len(timeline.actions) > 0
    )
    final_status = "contained" if is_contained else "failed"
    close_incident(incident_id=incident_id, status=final_status)

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
        status=final_status,
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
    print(f"Final Status     : {run.status.upper()}")
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
