"""Tests for BaseAgent execution loop, tool logging, and graph-path grounding enforcement."""

import json
from typing import Any, Dict, List
from src.agents.base import BaseAgent
from src.models import AttackPath, GraphPath
from src.queries import find_attack_paths


def test_base_agent_tool_calling_and_path_grounding() -> None:
    """Verify mocked LLM tool invocation logs tool calls and preserves graph path."""
    call_count = 0

    def mock_llm_client(
        messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        nonlocal call_count
        call_count += 1
        if call_count == 1:
            # First turn: model decides to call find_attack_paths tool
            return {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "call_attack_path_01",
                        "type": "function",
                        "function": {
                            "name": "find_attack_paths",
                            "arguments": json.dumps({"service_name": "payments-api"}),
                        },
                    }
                ],
            }
        # Second turn: model answers using the tool result
        return {
            "role": "assistant",
            "content": "Analysis complete: payments-api has an attack path to CustomerPIIStore.",
        }

    agent = BaseAgent(name="TestSecurityAgent", llm_client=mock_llm_client)
    agent.register_tool(
        name="find_attack_paths",
        func=find_attack_paths,
        description="Find shortest attack paths to crown jewels",
        parameters={
            "type": "object",
            "properties": {"service_name": {"type": "string"}},
            "required": ["service_name"],
        },
    )

    result = agent.run(task="Check payments-api blast radius", context={"service": "payments-api"})

    # Assertions
    assert result.success is True
    assert "payments-api has an attack path" in result.answer
    assert result.graph_path is not None
    assert isinstance(result.graph_path, GraphPath)
    assert len(result.graph_path.nodes) >= 3
    assert len(result.graph_path.edges) >= 2
    assert "payments-api" in result.graph_path.readable

    # Assert tool call logging
    assert len(result.tool_calls) == 1
    log = result.tool_calls[0]
    assert log["name"] == "find_attack_paths"
    assert log["args"] == {"service_name": "payments-api"}
    assert "CustomerPIIStore" in log["result_summary"]
    assert "timestamp" in log


def test_base_agent_rejects_answer_without_graph_path() -> None:
    """Verify that an agent answer without a Cypher-derived graph path is rejected with an error."""
    def mock_fabricating_llm(
        messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        # LLM attempts to answer without calling any graph tools
        return {
            "role": "assistant",
            "content": "I believe the service is totally safe and there are no vulnerabilities.",
        }

    agent = BaseAgent(name="FabricatingAgent", llm_client=mock_fabricating_llm)
    result = agent.run(task="Assess payments-api", context={})

    assert result.success is False
    assert result.graph_path is None
    assert "Error: Decision rejected" in result.answer
    assert "No Cypher-derived graph path" in result.answer


def test_base_agent_json_in_text_protocol() -> None:
    """Verify agent handles strict JSON-in-text tool calling protocol as fallback."""
    step = 0

    def mock_json_llm(
        messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        nonlocal step
        step += 1
        if step == 1:
            return {
                "role": "assistant",
                "content": json.dumps({
                    "tool": "find_attack_paths",
                    "args": {"service_name": "payments-api"},
                }),
            }
        return {
            "role": "assistant",
            "content": "Remediation justified based on verified graph path.",
        }

    agent = BaseAgent(name="JsonAgent", llm_client=mock_json_llm)
    agent.register_tool(
        name="find_attack_paths",
        func=find_attack_paths,
        description="Find attack paths",
        parameters={"type": "object", "properties": {"service_name": {"type": "string"}}},
    )

    result = agent.run(task="Run path analysis", context={})
    assert result.success is True
    assert result.graph_path is not None
    assert len(result.tool_calls) == 1
    assert result.tool_calls[0]["name"] == "find_attack_paths"
