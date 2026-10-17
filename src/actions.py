"""Mocked and audited incident mitigation actions and chronological timeline tracking."""

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

from src.models import ActionResult
from src.queries import record_incident_action


class Timeline:
    """Chronological event accumulator tracking executed incident actions for UI rendering."""

    def __init__(self) -> None:
        """Initialize an empty incident action timeline."""
        self._actions: List[ActionResult] = []

    def add(self, action: ActionResult) -> None:
        """Append an executed action result to the incident timeline."""
        self._actions.append(action)

    @property
    def actions(self) -> List[ActionResult]:
        """Return the ordered list of action results."""
        return list(self._actions)

    def to_list(self) -> List[Dict[str, Any]]:
        """Serialize all timeline events into dictionary records for UI display."""
        return [action.model_dump() for action in self._actions]

    def clear(self) -> None:
        """Clear all accumulated timeline records."""
        self._actions.clear()


# Default process-level timeline instance
default_timeline = Timeline()


def _get_timestamp() -> str:
    """Return the current ISO-8601 UTC timestamp."""
    return datetime.now(timezone.utc).isoformat()


def isolate_host(
    asset: str, incident_id: Optional[str] = None, timeline: Optional[Timeline] = None
) -> ActionResult:
    """Quarantine a compromised server or container host by applying network isolation."""
    ts = _get_timestamp()
    log_line = f"[ISOLATE_HOST] Quarantined host '{asset}' via network security group ingress/egress cut."
    result = ActionResult(
        action_type="ISOLATE_HOST",
        target=asset,
        status="SUCCESS",
        timestamp=ts,
        log_line=log_line,
        details={"asset": asset, "incident_id": incident_id},
    )
    (timeline or default_timeline).add(result)
    if incident_id:
        result.details["action_id"] = record_incident_action(incident_id, "ISOLATE_HOST", asset, "SUCCESS", log_line)
    return result


def open_ticket(
    service: str, summary: str, assignee: str, incident_id: Optional[str] = None, timeline: Optional[Timeline] = None
) -> ActionResult:
    """Create an incident tracking ticket in Jira/Linear assigned to the service owner."""
    ts = _get_timestamp()
    ticket_key = f"SEC-{abs(hash(summary)) % 9000 + 1000}"
    log_line = f"[OPEN_TICKET] Opened ticket {ticket_key} for {service} assigned to {assignee}: {summary}"
    result = ActionResult(
        action_type="OPEN_TICKET",
        target=ticket_key,
        status="SUCCESS",
        timestamp=ts,
        log_line=log_line,
        details={"ticket": ticket_key, "service": service, "assignee": assignee, "summary": summary},
    )
    (timeline or default_timeline).add(result)
    if incident_id:
        result.details["action_id"] = record_incident_action(incident_id, "OPEN_TICKET", ticket_key, "SUCCESS", log_line)
    return result


def page_on_call(
    person: str, service: str, severity: str, incident_id: Optional[str] = None, timeline: Optional[Timeline] = None
) -> ActionResult:
    """Dispatch an emergency pager notification to the designated on-call engineer."""
    ts = _get_timestamp()
    log_line = f"[PAGE_ONCALL] Dispatched {severity} alert to on-call '{person}' for service '{service}'."
    result = ActionResult(
        action_type="PAGE_ONCALL",
        target=person,
        status="SUCCESS",
        timestamp=ts,
        log_line=log_line,
        details={"person": person, "service": service, "severity": severity},
    )
    (timeline or default_timeline).add(result)
    if incident_id:
        result.details["action_id"] = record_incident_action(incident_id, "PAGE_ONCALL", person, "SUCCESS", log_line)
    return result


def start_runbook_step(
    incident_id: str, step_name: str, timeline: Optional[Timeline] = None
) -> ActionResult:
    """Initiate an incident response runbook mitigation procedure."""
    ts = _get_timestamp()
    log_line = f"[RUNBOOK_STEP] Initiated runbook procedure '{step_name}' for incident {incident_id}."
    result = ActionResult(
        action_type="START_RUNBOOK_STEP",
        target=step_name,
        status="SUCCESS",
        timestamp=ts,
        log_line=log_line,
        details={"step_name": step_name, "incident_id": incident_id},
    )
    (timeline or default_timeline).add(result)
    result.details["action_id"] = record_incident_action(incident_id, "START_RUNBOOK_STEP", step_name, "SUCCESS", log_line)
    return result


def switch_runbook_step(
    incident_id: str, from_step: str, to_step: str, reason: str, timeline: Optional[Timeline] = None
) -> ActionResult:
    """Divert runbook execution from a failing step to an alternate mitigation path."""
    ts = _get_timestamp()
    log_line = f"[SWITCH_RUNBOOK_STEP] Diverted runbook from '{from_step}' to '{to_step}'. Reason: {reason}"
    result = ActionResult(
        action_type="SWITCH_RUNBOOK_STEP",
        target=to_step,
        status="SUCCESS",
        timestamp=ts,
        log_line=log_line,
        details={"from_step": from_step, "to_step": to_step, "reason": reason, "incident_id": incident_id},
    )
    (timeline or default_timeline).add(result)
    result.details["action_id"] = record_incident_action(incident_id, "SWITCH_RUNBOOK_STEP", to_step, "SUCCESS", log_line)
    return result


def post_incident_update(
    incident_id: str, message: str, timeline: Optional[Timeline] = None
) -> ActionResult:
    """Publish a broadcast status update to incident response communication channels."""
    ts = _get_timestamp()
    log_line = f"[POST_UPDATE] Broadcast update for {incident_id}: {message}"
    result = ActionResult(
        action_type="POST_UPDATE",
        target=incident_id,
        status="SUCCESS",
        timestamp=ts,
        log_line=log_line,
        details={"incident_id": incident_id, "message": message},
    )
    (timeline or default_timeline).add(result)
    result.details["action_id"] = record_incident_action(incident_id, "POST_UPDATE", incident_id, "SUCCESS", log_line)
    return result
