"""Tests for CommanderAgent decision loop, action execution, and memory recall."""

import json
from src.agents.commander import CommanderAgent
from src.db import get_graph
from src.models import CommanderResult, GraphPath


def test_commander_execution_on_payments_api() -> None:
    """Run CommanderAgent on payments-api with CRITICAL CVE and assert decisions, paths, and actions."""
    commander = CommanderAgent()
    inc_id = "inc-2024-test-cmd"

    result = commander.command(
        incident_id=inc_id, service="payments-api", cve="CVE-2024-3094"
    )

    try:
        # 1. Assert result is valid CommanderResult and succeeded
        assert isinstance(result, CommanderResult)
        assert result.success is True
        assert result.service == "payments-api"
        assert result.cve == "CVE-2024-3094"

        # 2. Assert 4+ actions executed
        assert len(result.action_timeline) >= 4
        action_types = [a["action_type"] for a in result.action_timeline]
        assert "ISOLATE_HOST" in action_types
        assert "OPEN_TICKET" in action_types
        assert "PAGE_ONCALL" in action_types
        assert "SWITCH_RUNBOOK_STEP" in action_types

        # 3. Assert at least 2 graph paths cited
        assert len(result.graph_paths) >= 2
        for p in result.graph_paths:
            assert isinstance(p, GraphPath)
            assert "-[:" in p.readable or "<-[:" in p.readable

        # 4. Assert memory recommendation honored (switched step and cited past episode)
        assert "mem-ep-payments-01" in result.memory_influence
        assert "VPC Security Group Egress Lockdown" in result.memory_influence
        assert "FAILED" in result.memory_influence

        # 5. Assert memory episode written
        assert result.episode_id is not None
        assert result.episode_id.startswith("mem-")

        # Verify new memory episode exists in FalkorDB
        g = get_graph()
        check_q = "MATCH (m:MemoryEpisode {id: $id}) RETURN m.id, m.service, m.outcome"
        res = g.query(check_q, {"id": result.episode_id}).result_set
        assert len(res) == 1
        assert res[0][1] == "payments-api"

        # Print full result for verification
        print("\n" + "=" * 65)
        print("           COMMANDER AGENT EXECUTION RESULT           ")
        print("=" * 65)
        print(f"Incident ID      : {result.incident_id}")
        print(f"Service          : {result.service}")
        print(f"CVE              : {result.cve}")
        print(f"Summary          :\n{result.summary}")
        print(f"\nMemory Influence :\n{result.memory_influence}")
        print(f"\nNew Episode ID   : {result.episode_id}")
        print(f"\nGraph Paths Cited ({len(result.graph_paths)}):")
        for i, p in enumerate(result.graph_paths, 1):
            print(f"  {i}. {p.readable}")
        print(f"\nAction Timeline ({len(result.action_timeline)} events):")
        for i, a in enumerate(result.action_timeline, 1):
            print(f"  {i}. [{a['action_type']}] -> {a['target']} ({a['status']})")
        print("=" * 65)

    finally:
        # Clean up test episode
        if result.episode_id:
            g = get_graph()
            g.query("MATCH (m:MemoryEpisode {id: $id}) DETACH DELETE m", {"id": result.episode_id})
