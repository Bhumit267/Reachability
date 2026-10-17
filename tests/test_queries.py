"""Automated tests for all graph Cypher query functions against seed data."""

import uuid
from src.models import (
    AttackPath,
    CodeImpact,
    CveAssessment,
    IncidentTimeline,
    MemoryEpisodeModel,
    OwnerOnCall,
    ServiceModel,
)
from src.queries import (
    find_attack_paths,
    find_similar_incidents,
    get_affected_assets,
    get_code_impact,
    get_incident_timeline,
    get_owners_and_oncall,
    get_service,
    rank_cves_by_reachability,
    write_memory_episode,
)


def test_get_service() -> None:
    """Verify get_service retrieves typed metadata for payments-api."""
    service = get_service("payments-api")
    assert service is not None
    assert isinstance(service, ServiceModel)
    assert service.name == "payments-api"
    assert service.critical is True
    assert service.language == "python"

    # Graceful handling of non-existent service
    assert get_service("non-existent-service") is None


def test_find_attack_paths() -> None:
    """Verify find_attack_paths returns shortest paths to crown jewels with risk scoring."""
    paths = find_attack_paths("payments-api")
    assert len(paths) > 0
    assert isinstance(paths[0], AttackPath)

    crown_jewels = {ap.crown_jewel for ap in paths}
    assert "PaymentLedger" in crown_jewels or "CustomerPIIStore" in crown_jewels

    for ap in paths:
        assert ap.hops >= 2
        assert 0.0 <= ap.risk_score <= 10.0
        assert "payments-api" in ap.path.readable
        assert len(ap.path.nodes) >= 3
        assert len(ap.path.edges) >= 2


def test_rank_cves_by_reachability() -> None:
    """Verify rank_cves_by_reachability sorts CVEs by CVSS and crown jewel exposure."""
    cves = rank_cves_by_reachability("payments-api")
    assert len(cves) > 0
    assert isinstance(cves[0], CveAssessment)

    top_cve = cves[0]
    assert top_cve.cve == "CVE-2024-3094"
    assert top_cve.severity == "CRITICAL"
    assert "k8s-node-payments-prod-01" in top_cve.affected_assets
    assert len(top_cve.reachable_crown_jewels) > 0
    assert "PaymentLedger" in top_cve.reachable_crown_jewels
    assert "CVSS 10.0" in top_cve.rank_reason


def test_get_affected_assets() -> None:
    """Verify get_affected_assets returns all infrastructure assets hosting payments-api."""
    assets = get_affected_assets("payments-api")
    assert len(assets) >= 2
    assert "k8s-node-payments-prod-01" in assets
    assert "rds-pg-payments-master" in assets


def test_get_code_impact() -> None:
    """Verify get_code_impact maps service to repo, files, functions, owner, and on-call."""
    impact = get_code_impact("payments-api")
    assert impact is not None
    assert isinstance(impact, CodeImpact)
    assert impact.service == "payments-api"
    assert impact.repo == "payments-api-service"
    assert "src/payment_handler.py" in impact.files
    assert "process_payment" in impact.functions
    assert impact.owner == "Alice Smith"
    assert impact.on_call == "Payments On-Call Primary"


def test_get_owners_and_oncall() -> None:
    """Verify get_owners_and_oncall returns lead owner and primary on-call rotation."""
    info = get_owners_and_oncall("payments-api")
    assert info is not None
    assert isinstance(info, OwnerOnCall)
    assert info.service == "payments-api"
    assert info.owner_name == "Alice Smith"
    assert info.team == "Payments Core Team"
    assert info.oncall_name == "Payments On-Call Primary"
    assert info.oncall_phone == "+1-555-0101"
    assert info.active is True


def test_find_similar_incidents() -> None:
    """Verify find_similar_incidents recalls memory episodes with failed runbook step."""
    episodes = find_similar_incidents("payments-api", limit=5)
    assert len(episodes) > 0
    assert isinstance(episodes[0], MemoryEpisodeModel)

    # Check for seed incident memory
    seed_episodes = [e for e in episodes if e.id == "mem-ep-payments-01"]
    assert len(seed_episodes) > 0
    ep = seed_episodes[0]
    assert ep.service == "payments-api"
    assert "WAF" in ep.summary or "lockdown" in ep.summary.lower()

    # Verify memory contains record of the failed runbook step
    has_failed_step = any(not e.success for e in episodes)
    assert has_failed_step, "Expected at least one failed runbook step in past incident memory"


def test_write_memory_episode() -> None:
    """Verify write_memory_episode persists a new memory node in the graph."""
    from src.db import get_graph

    test_id = f"mem-test-{uuid.uuid4().hex[:8]}"
    episode = MemoryEpisodeModel(
        id=test_id,
        summary="Automated test memory episode for verification",
        service="payments-api",
        outcome="Host isolated via egress rule; zero transaction loss",
        runbook_step="VPC Security Group Lockdown",
        success=True,
        timestamp="2026-10-17T12:00:00Z",
    )
    try:
        written = write_memory_episode(episode)
        assert written.id == test_id
        assert written.service == "payments-api"
        assert written.success is True

        # Retrieve and verify persistence
        similar = find_similar_incidents("payments-api", limit=10)
        matching = [e for e in similar if e.id == test_id]
        assert len(matching) == 1
        assert matching[0].runbook_step == "VPC Security Group Lockdown"
    finally:
        g = get_graph()
        g.query("MATCH (m:MemoryEpisode {id: $id}) DETACH DELETE m", {"id": test_id})


def test_get_incident_timeline() -> None:
    """Verify get_incident_timeline aggregates chronological actions and runbook steps."""
    timeline = get_incident_timeline("inc-2024-0821")
    assert timeline is not None
    assert isinstance(timeline, IncidentTimeline)
    assert timeline.incident_id == "inc-2024-0821"
    assert timeline.service == "payments-api"
    assert len(timeline.events) >= 5

    action_events = [e for e in timeline.events if e.event_type == "ACTION"]
    step_events = [e for e in timeline.events if e.event_type == "RUNBOOK_STEP"]

    assert len(action_events) >= 3
    assert len(step_events) >= 2
    assert any(e.status == "FAILED" for e in step_events)
