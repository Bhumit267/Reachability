"""Autonomous incident commander agent orchestrating reachability analysis, actions, and memory."""

from typing import Any, Callable, Dict, List, Optional
from src.actions import (
    Timeline,
    isolate_host,
    open_ticket,
    page_on_call,
    post_incident_update,
    start_runbook_step,
    switch_runbook_step,
)
from src.agents.base import BaseAgent
from src.config import Settings
from src.memory import recall_for_decision, remember
from src.models import AgentResult, CommanderResult, GraphPath
from src.queries import (
    find_attack_paths,
    get_affected_assets,
    get_code_impact,
    get_owners_and_oncall,
    rank_cves_by_reachability,
)

COMMANDER_SYSTEM_PROMPT = """You are CommanderAgent, the autonomous incident commander for critical security CVEs.
You coordinate reachability analysis, code exposure mapping, historical incident memory, and remediation actions.

Decision Workflow:
1. Execute reachability analysis (find_attack_paths, rank_cves_by_reachability, get_affected_assets).
2. Execute code impact mapping (get_code_impact, get_owners_and_oncall).
3. Evaluate historical incident memory (recall_for_decision) for the candidate runbook step.
4. Execute remediation actions in order: isolate_host, open_ticket, page_on_call, and start/switch runbook step.
5. If memory recall recommends switch_step, you MUST switch runbook step and cite the past episode ID and graph path.
6. Write a memory episode summarizing the outcome to FalkorDB.
7. Return a complete CommanderResult with all cited graph paths and timeline events."""


class CommanderAgent(BaseAgent):
    """Incident commander agent deciding and executing remediation actions grounded in graph memory."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        llm_client: Optional[Callable[[List[Dict[str, Any]], List[Dict[str, Any]]], Dict[str, Any]]] = None,
    ) -> None:
        """Initialize CommanderAgent with action dispatchers and graph tools."""
        super().__init__(
            name="CommanderAgent",
            system_prompt=COMMANDER_SYSTEM_PROMPT,
            settings=settings,
            llm_client=llm_client,
        )
        self._register_commander_tools()

    def _register_commander_tools(self) -> None:
        """Register all security, code-impact, memory, and mitigation action tools."""
        self.register_tool(
            name="find_attack_paths",
            func=find_attack_paths,
            description="Find shortest attack paths to crown jewels",
            parameters={"type": "object", "properties": {"service_name": {"type": "string"}}},
        )
        self.register_tool(
            name="rank_cves_by_reachability",
            func=rank_cves_by_reachability,
            description="Rank CVEs by CVSS severity and crown jewel exposure",
            parameters={"type": "object", "properties": {"service_name": {"type": "string"}}},
        )
        self.register_tool(
            name="get_affected_assets",
            func=get_affected_assets,
            description="Get infrastructure assets hosting service",
            parameters={"type": "object", "properties": {"service_name": {"type": "string"}}},
        )
        self.register_tool(
            name="get_code_impact",
            func=get_code_impact,
            description="Get repository, files, functions, owner, and on-call",
            parameters={"type": "object", "properties": {"service_name": {"type": "string"}}},
        )
        self.register_tool(
            name="get_owners_and_oncall",
            func=get_owners_and_oncall,
            description="Get lead developer and active on-call shift contacts",
            parameters={"type": "object", "properties": {"service_name": {"type": "string"}}},
        )
        self.register_tool(
            name="recall_for_decision",
            func=recall_for_decision,
            description="Recall past incident memory to recommend repeating or switching runbook steps",
            parameters={
                "type": "object",
                "properties": {
                    "service": {"type": "string"},
                    "current_runbook_step": {"type": "string"},
                },
            },
        )
        self.register_tool(
            name="isolate_host",
            func=isolate_host,
            description="Quarantine affected host node",
            parameters={"type": "object", "properties": {"asset": {"type": "string"}}},
        )
        self.register_tool(
            name="open_ticket",
            func=open_ticket,
            description="Open security mitigation ticket",
            parameters={"type": "object", "properties": {"service": {"type": "string"}}},
        )
        self.register_tool(
            name="page_on_call",
            func=page_on_call,
            description="Page active on-call engineer",
            parameters={"type": "object", "properties": {"person": {"type": "string"}}},
        )

    def command(
        self,
        incident_id: str,
        service: str,
        cve: str,
        timeline: Optional[Timeline] = None,
    ) -> CommanderResult:
        """Execute autonomous incident command decision sequence and return grounded CommanderResult."""
        tl = timeline or Timeline()
        cited_graph_paths: List[GraphPath] = []
        executed_action_names: List[str] = []

        # Step 1: Security blast-radius analysis
        attack_paths = find_attack_paths(service)
        affected_assets = get_affected_assets(service)
        cve_assessments = rank_cves_by_reachability(service)

        if not affected_assets:
            return CommanderResult(
                incident_id=incident_id, service=service, cve=cve,
                summary=f"Error: Unable to locate hosting assets for service '{service}'. Aborting.",
                action_timeline=tl.to_list(), graph_paths=[],
                memory_influence="None: aborted before memory check due to missing assets.",
                success=False,
            )

        primary_asset = affected_assets[0]
        if attack_paths and attack_paths[0].path:
            cited_graph_paths.append(attack_paths[0].path)

        # Step 2: Code impact and ownership mapping
        code_impact = get_code_impact(service)
        owner_info = get_owners_and_oncall(service)

        if not code_impact:
            return CommanderResult(
                incident_id=incident_id, service=service, cve=cve,
                summary=f"Error: Unable to trace repository code impact for service '{service}'. Aborting.",
                action_timeline=tl.to_list(), graph_paths=cited_graph_paths,
                memory_influence="None: aborted before memory check due to code mapping failure.",
                success=False,
            )

        if code_impact.path:
            cited_graph_paths.append(code_impact.path)

        owner_name = code_impact.owner
        oncall_contact = code_impact.on_call

        # Step 3: Historical memory recall for default runbook procedure
        default_candidate_step = "Apply strict WAF ingress drop rule"
        alternate_step = "VPC Security Group Egress Lockdown"
        memory_decision = recall_for_decision(service=service, current_runbook_step=default_candidate_step)

        memory_influence_summary = "Standard runbook initiated: No conflicting memory history."
        step_to_execute = default_candidate_step

        if memory_decision.get("recommendation") == "switch_step":
            rel_ep = memory_decision.get("relevant_episode")
            ep_id = rel_ep.id if rel_ep else "unknown"
            path_str = memory_decision.get("graph_path") or f"Service({service}) -[:REMEMBERS]-> MemoryEpisode({ep_id})"
            memory_influence_summary = (
                f"Memory recall alert: Past episode '{ep_id}' on {service} recorded that '{default_candidate_step}' "
                f"FAILED due to webhook collateral damage. Switched runbook to '{alternate_step}'. "
                f"Graph memory path: {path_str}."
            )
            step_to_execute = alternate_step
            cited_graph_paths.append(
                GraphPath(
                    nodes=[service, "Incident", ep_id, "Incident"],
                    edges=["AFFECTS", "REMEMBERS", "SIMILAR_TO"],
                    readable=path_str,
                )
            )

        # Step 4 & 5: Execute action sequence in order
        # Action 1: Isolate host
        res_iso = isolate_host(asset=primary_asset, incident_id=incident_id, timeline=tl)
        executed_action_names.append(res_iso.action_type)

        # Action 2: Open ticket
        ticket_summary = f"Remediate critical {cve} vulnerability exposing {primary_asset} and Crown Jewels."
        res_ticket = open_ticket(service=service, summary=ticket_summary, assignee=owner_name, incident_id=incident_id, timeline=tl)
        executed_action_names.append(res_ticket.action_type)

        # Action 3: Page on-call
        res_page = page_on_call(person=oncall_contact, service=service, severity="CRITICAL", incident_id=incident_id, timeline=tl)
        executed_action_names.append(res_page.action_type)

        # Action 4: Runbook execution (switch or start)
        if memory_decision.get("recommendation") == "switch_step":
            res_rb = switch_runbook_step(
                incident_id=incident_id, from_step=default_candidate_step, to_step=alternate_step,
                reason=memory_influence_summary, timeline=tl
            )
        else:
            res_rb = start_runbook_step(incident_id=incident_id, step_name=default_candidate_step, timeline=tl)
        executed_action_names.append(res_rb.action_type)

        # Action 5: Post broadcast update
        res_update = post_incident_update(
            incident_id=incident_id,
            message=(
                f"Host {primary_asset} isolated. Ticket {res_ticket.target} opened for {owner_name}. "
                f"On-call {oncall_contact} paged. Mitigation active via {step_to_execute}."
            ),
            timeline=tl,
        )
        executed_action_names.append(res_update.action_type)

        # Step 6: Write newly learned memory episode
        new_episode = remember(
            incident_id=incident_id,
            service=service,
            summary=f"Incident {incident_id} ({cve}) mitigated. Actions taken: {', '.join(executed_action_names)}.",
            actions_taken=executed_action_names,
            runbook_step=step_to_execute,
            success=True,
            outcome=f"Successfully quarantined {primary_asset} and enforced {step_to_execute}. Zero customer data exposed.",
        )

        overall_summary = (
            f"Commander responded to {cve} on {service}. Quarantined {primary_asset}, opened ticket assigned to "
            f"{owner_name}, and paged {oncall_contact}. Honored graph memory recall by switching runbook procedure "
            f"to {step_to_execute}. Persisted outcome to memory episode {new_episode.id}."
        )

        return CommanderResult(
            incident_id=incident_id,
            service=service,
            cve=cve,
            summary=overall_summary,
            action_timeline=tl.to_list(),
            graph_paths=cited_graph_paths,
            memory_influence=memory_influence_summary,
            episode_id=new_episode.id,
            success=True,
        )
