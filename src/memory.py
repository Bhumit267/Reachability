"""Graph-native incident memory management, episode storage, and decision recall."""

import uuid
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from falkordb import Graph

from src.models import MemoryEpisodeModel
from src.queries import find_similar_incidents, link_memory_episode, write_memory_episode


def remember(
    incident_id: str,
    service: str,
    summary: str,
    actions_taken: List[str],
    runbook_step: Any,
    success: bool,
    outcome: str,
    graph: Optional[Graph] = None,
) -> MemoryEpisodeModel:
    """Store an incident memory episode and link SIMILAR_TO edges to past incidents in FalkorDB."""
    episode_id = f"mem-{uuid.uuid4().hex[:8]}"
    actions_summary = f" Actions: {', '.join(actions_taken)}." if actions_taken else ""
    full_summary = f"{summary.strip()}{actions_summary}"
    timestamp = datetime.now(timezone.utc).isoformat()

    step_str = f"Step {runbook_step}" if str(runbook_step).isdigit() else str(runbook_step)

    episode = MemoryEpisodeModel(
        id=episode_id,
        summary=full_summary,
        service=service,
        outcome=outcome,
        runbook_step=step_str,
        success=success,
        timestamp=timestamp,
    )

    persisted = write_memory_episode(episode, graph=graph)
    link_memory_episode(episode_id=episode_id, service_name=service, incident_id=incident_id, graph=graph)
    return persisted


def recall(service: str, limit: int = 3, graph: Optional[Graph] = None) -> List[MemoryEpisodeModel]:
    """Retrieve historical memory episodes and lessons learned for the specified service."""
    return find_similar_incidents(service_name=service, limit=limit, graph=graph)


def _step_matches(episode_step: str, target_step: Any) -> bool:
    """Check if an episode runbook step matches the target step by number, name, or substring."""
    if target_step is None:
        return False
    target = str(target_step).strip().lower()
    ep = str(episode_step).strip().lower()

    if target == ep:
        return True
    if target in ep or ep in target:
        return True
    if target.isdigit():
        if f"step {target}" in ep or f"step #{target}" in ep or f"step-{target}" in ep:
            return True
    return False


def recall_for_decision(
    service: str,
    current_runbook_step: Any = None,
    step: Any = None,
    graph: Optional[Graph] = None,
) -> Dict[str, Any]:
    """Evaluate past memory episodes to recommend repeating, switching, or default execution."""
    target_step = step if step is not None else current_runbook_step
    episodes = recall(service=service, limit=10, graph=graph)

    # Search for matching historical runbook steps
    for ep in episodes:
        if _step_matches(ep.runbook_step, target_step):
            path_str = f"Service({service}) <-[:AFFECTS]- Incident -[:REMEMBERS]-> MemoryEpisode({ep.id}) -[:SIMILAR_TO]-> Incident"
            if not ep.success:
                return {
                    "has_history": True,
                    "relevant_episode": ep,
                    "recommendation": "switch_step",
                    "reason": (
                        f"Past episode '{ep.id}' on service '{service}' recorded that runbook step "
                        f"'{ep.runbook_step}' FAILED. Graph path: {path_str}. "
                        f"Prior outcome: {ep.outcome}. Recommendation: switch runbook step to avoid failure."
                    ),
                    "graph_path": path_str,
                }
            return {
                "has_history": True,
                "relevant_episode": ep,
                "recommendation": "repeat",
                "reason": (
                    f"Past episode '{ep.id}' on service '{service}' recorded that runbook step "
                    f"'{ep.runbook_step}' succeeded. Graph path: {path_str}."
                ),
                "graph_path": path_str,
            }

    return {
        "has_history": False,
        "relevant_episode": None,
        "recommendation": "none",
        "reason": f"No past incident history found for runbook step '{target_step}' on service '{service}'.",
        "graph_path": None,
    }
