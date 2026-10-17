"""Code-impact agent mapping services to repositories, code files, functions, and owners."""

from typing import Any, Callable, Dict, List, Optional

from src.agents.base import BaseAgent
from src.config import Settings
from src.models import AgentResult, CodeImpact, OwnerOnCall
from src.queries import get_code_impact, get_owners_and_oncall

CODE_IMPACT_SYSTEM_PROMPT = """You are CodeImpactAgent, an autonomous security agent mapping vulnerabilities to code repositories, source files, functions, and responsible engineers.

Required Procedure:
1. Call get_code_impact(service) to map service -> repo -> files -> functions -> owner -> on-call.
2. Call get_owners_and_oncall(service) to retrieve engineer ownership and active on-call shift details.

Response Guidelines:
- Write exactly 3 to 5 concise sentences.
- Specifically state:
  a) The repository name and key exposed files and functions.
  b) The service owner and active on-call engineer/schedule.
  c) The most likely file and function to patch and why based on graph proximity (e.g. primary entry-point handler in payment_handler.py).
- Do NOT decide remediation actions or write to memory.
- Ground your answer in the Cypher-derived graph path."""


class CodeImpactAgent(BaseAgent):
    """Agent determining code exposure, function entry points, and owner notification paths."""

    def __init__(
        self,
        settings: Optional[Settings] = None,
        llm_client: Optional[Callable[[List[Dict[str, Any]], List[Dict[str, Any]]], Dict[str, Any]]] = None,
    ) -> None:
        """Initialize CodeImpactAgent and register repository and ownership graph tools."""
        super().__init__(
            name="CodeImpactAgent",
            system_prompt=CODE_IMPACT_SYSTEM_PROMPT,
            settings=settings,
            llm_client=llm_client,
        )
        self._register_code_tools()

    def _register_code_tools(self) -> None:
        """Register code impact and on-call directory graph tools."""
        self.register_tool(
            name="get_code_impact",
            func=self._tool_get_code_impact,
            description="Map a service to its repository, source files, declared functions, owner, and on-call",
            parameters={
                "type": "object",
                "properties": {
                    "service": {"type": "string", "description": "Canonical service name, e.g. payments-api"}
                },
                "required": ["service"],
            },
        )
        self.register_tool(
            name="get_owners_and_oncall",
            func=self._tool_get_owners_and_oncall,
            description="Look up lead owner and on-call contact details for the specified service",
            parameters={
                "type": "object",
                "properties": {
                    "service": {"type": "string", "description": "Canonical service name, e.g. payments-api"}
                },
                "required": ["service"],
            },
        )

    def _tool_get_code_impact(
        self, service: Optional[str] = None, service_name: Optional[str] = None
    ) -> Optional[CodeImpact]:
        """Wrap get_code_impact handling service parameter aliases."""
        target = (service or service_name or "").strip()
        return get_code_impact(target)

    def _tool_get_owners_and_oncall(
        self, service: Optional[str] = None, service_name: Optional[str] = None
    ) -> Optional[OwnerOnCall]:
        """Wrap get_owners_and_oncall handling service parameter aliases."""
        target = (service or service_name or "").strip()
        return get_owners_and_oncall(target)

    def analyze(self, service: str, cve: str) -> AgentResult:
        """Analyze repository exposure, functions to patch, and ownership contacts for a CVE."""
        task = (
            f"Analyze the code impact and developer ownership for {cve} affecting {service}.\n"
            f"Identify the repository, exposed files/functions, service owner, on-call engineer, "
            f"and the most likely file and function to patch."
        )
        context = {"service": service, "cve": cve}
        return self.run(task=task, context=context)
