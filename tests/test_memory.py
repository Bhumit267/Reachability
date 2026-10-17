"""Tests for graph-native incident memory, episode persistence, and decision recall."""

from src.db import get_graph
from src.memory import recall, recall_for_decision, remember
from src.models import MemoryEpisodeModel


def test_memory_failed_step_recall_and_decision() -> None:
    """Verify writing a failed episode on payments-api triggers switch_step recommendation."""
    # 1. Write a failed episode on payments-api for runbook step 1
    episode = remember(
        incident_id="inc-test-mem-01",
        service="payments-api",
        summary="Ingress rate limit caused cascade outage on checkout",
        actions_taken=["ISOLATE_HOST", "APPLY_WAF_RULE"],
        runbook_step=1,
        success=False,
        outcome="WAF drop broke webhook loop. Switch step to VPC security group egress lockdown.",
    )

    try:
        assert isinstance(episode, MemoryEpisodeModel)
        assert episode.service == "payments-api"
        assert episode.success is False

        # 2. Call recall_for_decision("payments-api", step=1)
        decision = recall_for_decision("payments-api", step=1)

        # 3. Assert recommendation == "switch_step" and reason references the episode
        assert decision["has_history"] is True
        assert decision["recommendation"] == "switch_step"
        assert decision["relevant_episode"] is not None
        assert decision["relevant_episode"].id == episode.id
        assert episode.id in decision["reason"]
        assert "FAILED" in decision["reason"]
        assert decision["graph_path"] is not None
        assert "[:REMEMBERS]->" in decision["graph_path"]

    finally:
        # Clean up test node
        g = get_graph()
        g.query("MATCH (m:MemoryEpisode {id: $id}) DETACH DELETE m", {"id": episode.id})


def test_memory_successful_step_recall() -> None:
    """Verify writing a successful episode yields repeat recommendation."""
    episode = remember(
        incident_id="inc-test-mem-02",
        service="payments-api",
        summary="Direct host isolation succeeded cleanly",
        actions_taken=["CORDON_NODE"],
        runbook_step="cordon-host-node",
        success=True,
        outcome="Host was quarantined with zero traffic leakage.",
    )

    try:
        decision = recall_for_decision("payments-api", current_runbook_step="cordon-host-node")
        assert decision["has_history"] is True
        assert decision["recommendation"] == "repeat"
        assert episode.id in decision["reason"]
    finally:
        g = get_graph()
        g.query("MATCH (m:MemoryEpisode {id: $id}) DETACH DELETE m", {"id": episode.id})


def test_memory_no_history_recommendation() -> None:
    """Verify step without prior history returns recommendation 'none'."""
    decision = recall_for_decision("payments-api", step=999)
    assert decision["has_history"] is False
    assert decision["recommendation"] == "none"
    assert decision["relevant_episode"] is None


def test_memory_graph_native_edges() -> None:
    """Verify SIMILAR_TO edges are graph-native in FalkorDB."""
    episode = remember(
        incident_id="inc-2024-0821",
        service="payments-api",
        summary="Test graph native SIMILAR_TO linkage",
        actions_taken=["TEST_ACTION"],
        runbook_step="test-step",
        success=True,
        outcome="Test linkage OK",
    )

    try:
        g = get_graph()
        cypher = """
        MATCH (m:MemoryEpisode {id: $id})-[:SIMILAR_TO]->(inc:Incident)
        RETURN count(inc)
        """
        res = g.query(cypher, {"id": episode.id}).result_set
        similar_count = res[0][0] if res else 0
        assert similar_count >= 1, "Expected MemoryEpisode to be linked via SIMILAR_TO edge"
    finally:
        g = get_graph()
        g.query("MATCH (m:MemoryEpisode {id: $id}) DETACH DELETE m", {"id": episode.id})
