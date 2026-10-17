"""Security blast-radius agent evaluating vulnerability reachability to crown jewels."""

from typing import Any, Callable, Dict, List, Optional

from src.agents.base import BaseAgent
from src.config import Settings
from src.models import AgentResult, AttackPath, CveAssessment
from src.queries import find_attack_paths, get_affected_assets, rank_cves_by_reachability

SECURITY_AGENT_SYSTEM_PROMPT = """You are SecurityBlastRadiusAgent, an autonomous security agent specializing in graph reachability analysis.
Your job is to determine whether a given CVE on a target service exposes critical Crown Jewels.

Required Procedure:
1. Call get_affected_assets(service) to find the hosting assets.
2. Call rank_cves_by_reachability(service) to evaluate severity and reachability rank.
3. Call find_attack_paths(service) to discover the shortest path from vulnerable assets to Crown Jewels.

Response Guidelines:
- Write exactly 3 to 6 concise sentences summarizing:
  a) The affected infrastructure assets.
  b) The CVE severity and reachability rank.
  c) The specific Crown Jewels reachable (e.g. PaymentLedger, CustomerPIIStore) and hop distance.
  d) If no crown jewel is reachable, state that explicitly and report the shortest asset path found.
- Do NOT prescribe remediation actions (host isolation, runbooks, or tickets are the Commander's responsibility).
- Do NOT write to memory or call other agents.
- Ground your answer completely in the returned Cypher graph path."""


class SecurityAgent(BaseAgent):
    """Agent determining blast radius and attack paths from a CVE to Crown Jewels."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        llm_client: Optional[Callable[[List[Dict[str, Any]], List[Dict[str, Any]]], Dict[str, Any]]] = None,
    ) -> None:
        """Initialize the SecurityAgent and register blast-radius Cypher tools."""
        super().__init__(
            name="SecurityBlastRadiusAgent",
            system_prompt=SECURITY_AGENT_SYSTEM_PROMPT,
            settings=settings,
            llm_client=llm_client,
        )
        self._register_security_tools()

    def _register_security_tools(self) -> None:
        """Register reachability, asset inspection, and attack path graph tools."""
        self.register_tool(
            name="find_attack_paths",
            func=self._tool_find_attack_paths,
            description="Find shortest traversable paths from a service's assets to crown jewels",
            parameters={
                "type": "object",
                "properties": {
                    "service": {"type": "string", "description": "Canonical service name, e.g. payments-api"},
                    "cve": {"type": "string", "description": "Specific CVE ID to filter by, e.g. CVE-2024-3094"},
                },
                "required": ["service"],
            },
        )
        self.register_tool(
            name="rank_cves_by_reachability",
            func=self._tool_rank_cves,
            description="Rank all CVEs affecting a service by CVSS severity and crown jewel reachability",
            parameters={
                "type": "object",
                "properties": {
                    "service": {"type": "string", "description": "Canonical service name, e.g. payments-api"}
                },
                "required": ["service"],
            },
        )
        self.register_tool(
            name="get_affected_assets",
            func=self._tool_get_assets,
            description="List all hosting host/database/queue assets running the specified service",
            parameters={
                "type": "object",
                "properties": {
                    "service": {"type": "string", "description": "Canonical service name, e.g. payments-api"}
                },
                "required": ["service"],
            },
        )

    def _tool_find_attack_paths(
        self, service: Optional[str] = None, service_name: Optional[str] = None, cve: Optional[str] = None
    ) -> List[AttackPath]:
        """Wrap find_attack_paths handling service parameter aliases and optional CVE scope."""
        target = (service or service_name or "").strip()
        return find_attack_paths(service_name=target, cve_id=cve)

    def _tool_rank_cves(
        self, service: Optional[str] = None, service_name: Optional[str] = None
    ) -> List[CveAssessment]:
        """Wrap rank_cves_by_reachability handling service parameter aliases."""
        target = (service or service_name or "").strip()
        return rank_cves_by_reachability(target)

    def _tool_get_assets(
        self, service: Optional[str] = None, service_name: Optional[str] = None
    ) -> List[str]:
        """Wrap get_affected_assets handling service parameter aliases."""
        target = (service or service_name or "").strip()
        return get_affected_assets(target)

    def analyze(self, service: str, cve: str) -> AgentResult:
        """Execute blast-radius analysis for a specific CVE on a service."""
        task = (
            f"Analyze the blast radius and reachability of {cve} on {service}.\n"
            f"Determine affected infrastructure, reachability ranking, and shortest path to Crown Jewels."
        )
        context = {"service": service, "cve": cve}
        return self.run(task=task, context=context)
