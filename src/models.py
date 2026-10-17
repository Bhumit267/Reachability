"""Pydantic data models for graph queries, attack paths, and agent communication."""

from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class GraphPath(BaseModel):
    """Sequence of node and edge identifiers representing a path in the graph."""

    nodes: List[str] = Field(default_factory=list, description="Ordered list of node names or IDs")
    edges: List[str] = Field(default_factory=list, description="Ordered list of edge relationship types")
    readable: str = Field(..., description="Human-readable representation of the graph path")


class AttackPath(BaseModel):
    """Attack trajectory from an exposed service or asset to a critical Crown Jewel."""

    path: GraphPath = Field(..., description="Traversed graph path")
    crown_jewel: str = Field(..., description="Target crown jewel asset")
    hops: int = Field(..., ge=1, description="Number of hops in the path")
    risk_score: float = Field(..., ge=0.0, le=10.0, description="Computed risk score (0-10)")


class CveAssessment(BaseModel):
    """Vulnerability assessment ranked by reachability to crown jewels."""

    cve: str = Field(..., description="CVE identifier")
    severity: str = Field(..., description="Vulnerability severity level")
    affected_assets: List[str] = Field(default_factory=list, description="Assets running the vulnerable software")
    reachable_crown_jewels: List[str] = Field(
        default_factory=list, description="Crown jewels reachable from affected assets"
    )
    rank_reason: str = Field(..., description="Explanation of why this CVE received this priority")


class CodeImpact(BaseModel):
    """Code exposure and ownership mapping for a vulnerable service."""

    service: str = Field(..., description="Name of the vulnerable service")
    repo: str = Field(..., description="Repository containing service code")
    files: List[str] = Field(default_factory=list, description="Exposed code files")
    functions: List[str] = Field(default_factory=list, description="Exposed code functions")
    owner: str = Field(..., description="Lead engineer or owner of the service")
    on_call: str = Field(..., description="Active on-call engineer or rotation")
    path: Optional[GraphPath] = Field(
        default=None, description="Graph path connecting service to code and ownership"
    )


class MemoryEpisodeModel(BaseModel):
    """Record of a past incident response episode for agent memory recall."""

    id: str = Field(..., description="Unique episode identifier")
    summary: str = Field(..., description="Concise synopsis of the incident response")
    service: str = Field(..., description="Target service affected")
    outcome: str = Field(..., description="Resolution outcome or key takeaway")
    runbook_step: str = Field(..., description="Specific runbook step executed or failed")
    success: bool = Field(..., description="Whether the response step succeeded")
    timestamp: str = Field(..., description="ISO-8601 timestamp of the incident memory")


class ServiceModel(BaseModel):
    """Service metadata registered in the knowledge graph."""

    id: str = Field(..., description="Service node ID")
    name: str = Field(..., description="Canonical service name")
    tier: str = Field(..., description="Service criticality tier")
    critical: bool = Field(..., description="Whether the service is mission critical")
    language: str = Field(..., description="Primary programming language")


class OwnerOnCall(BaseModel):
    """Ownership and on-call operational contact details for a service."""

    service: str = Field(..., description="Service name")
    owner_name: str = Field(..., description="Owner full name")
    owner_email: str = Field(..., description="Owner email address")
    team: str = Field(..., description="Engineering team name")
    oncall_name: str = Field(..., description="On-call schedule or personnel name")
    oncall_phone: str = Field(..., description="On-call contact telephone number")
    oncall_schedule: str = Field(..., description="Active on-call shift schedule")
    active: bool = Field(..., description="Whether on-call rotation is currently active")


class TimelineEvent(BaseModel):
    """Individual chronological milestone in an incident lifecycle."""

    event_type: str = Field(..., description="Category: ACTION, RUNBOOK_STEP, or ALERT")
    name: str = Field(..., description="Event name or action identifier")
    status: str = Field(..., description="Execution status")
    timestamp: str = Field(..., description="Timestamp of execution")
    details: str = Field(default="", description="Detailed notes, failure reasons, or target")


class IncidentTimeline(BaseModel):
    """Aggregated timeline of actions and runbook executions for an incident."""

    incident_id: str = Field(..., description="Incident identifier")
    title: str = Field(..., description="Incident title")
    service: str = Field(..., description="Affected service")
    events: List[TimelineEvent] = Field(default_factory=list, description="Chronological incident events")


class ToolCallRecord(BaseModel):
    """Log record of an individual tool execution by an agent."""

    name: str = Field(..., description="Name of the invoked tool")
    args: dict = Field(default_factory=dict, description="Arguments passed to the tool")
    result_summary: str = Field(..., description="Summary of the tool output")
    timestamp: str = Field(..., description="ISO-8601 execution timestamp")


class AgentResult(BaseModel):
    """Structured output returned by an agent execution."""

    success: bool = Field(default=True, description="Whether execution succeeded with valid graph path")
    answer: str = Field(..., description="Final response or decision")
    graph_path: Optional[GraphPath] = Field(default=None, description="Cypher-derived graph path justifying decision")
    tool_calls: List[dict] = Field(default_factory=list, description="Chronological log of tool calls")
    raw: dict = Field(default_factory=dict, description="Raw LLM payload or internal metadata")


class ActionResult(BaseModel):
    """Execution record for an automated incident action or runbook modification."""

    action_type: str = Field(..., description="Action classification, e.g. ISOLATE_HOST")
    target: str = Field(..., description="Action target entity, host, ticket, or engineer")
    status: str = Field(default="SUCCESS", description="Execution status: SUCCESS or FAILED")
    timestamp: str = Field(..., description="ISO-8601 timestamp of execution")
    log_line: str = Field(..., description="Human-readable audit log message")
    details: Dict[str, Any] = Field(default_factory=dict, description="Supplemental action parameters")


class CommanderResult(BaseModel):
    """Aggregated incident command result including timeline, paths, and memory influence."""

    incident_id: str = Field(..., description="Incident identifier")
    service: str = Field(..., description="Target service affected")
    cve: str = Field(..., description="Target CVE identifier")
    summary: str = Field(..., description="Incident command summary")
    action_timeline: List[Dict[str, Any]] = Field(default_factory=list, description="Chronological action timeline")
    graph_paths: List[GraphPath] = Field(default_factory=list, description="All graph paths justifying decisions")
    memory_influence: str = Field(..., description="Detailed explanation of memory recall influence")
    episode_id: Optional[str] = Field(default=None, description="Persisted incident memory episode identifier")
    success: bool = Field(default=True, description="Overall execution status")



