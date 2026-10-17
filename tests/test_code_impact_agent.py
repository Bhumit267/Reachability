"""Tests for CodeImpactAgent mapping services to code repositories, files, and owners."""

import json
from typing import Any, Dict, List
from src.agents.code_impact_agent import CodeImpactAgent
from src.config import get_settings
from src.models import GraphPath


def test_code_impact_agent_mock_execution() -> None:
    """Verify CodeImpactAgent runs with mocked LLM and maps code to owners."""
    step = 0

    def mock_llm_client(
        messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        nonlocal step
        step += 1
        if step == 1:
            return {
                "role": "assistant",
                "content": None,
                "tool_calls": [
                    {
                        "id": "code_call_01",
                        "type": "function",
                        "function": {
                            "name": "get_code_impact",
                            "arguments": json.dumps({"service": "payments-api"}),
                        },
                    }
                ],
            }
        return {
            "role": "assistant",
            "content": (
                "The payments-api service maps to repository payments-api-service containing src/payment_handler.py. "
                "The primary entry point is process_payment, owned by Alice Smith with Payments On-Call Primary. "
                "The process_payment function in src/payment_handler.py is the most critical target to patch."
            ),
        }

    agent = CodeImpactAgent(llm_client=mock_llm_client)
    result = agent.analyze(service="payments-api", cve="CVE-2024-3094")

    assert result.success is True
    assert "payment_handler.py" in result.answer
    assert "process_payment" in result.answer
    assert "Alice Smith" in result.answer
    assert "Payments On-Call Primary" in result.answer
    assert result.graph_path is not None
    assert isinstance(result.graph_path, GraphPath)
    assert "payment_handler.py" in result.graph_path.readable
    assert "process_payment" in result.graph_path.readable
    assert "Alice Smith" in result.graph_path.readable


def test_code_impact_agent_live_execution() -> None:
    """Verify live CodeImpactAgent analysis on payments-api asserts code exposure and path."""
    cfg = get_settings()
    if not cfg.llm_api_key or cfg.llm_api_key == "mock-api-key":
        test_code_impact_agent_mock_execution()
        return

    agent = CodeImpactAgent()
    result = agent.analyze(service="payments-api", cve="CVE-2024-3094")

    assert result.success is True
    assert result.graph_path is not None
    assert isinstance(result.graph_path, GraphPath)

    # Assert output includes payment_handler.py, process_payment, owner, on-call
    combined_text = (result.answer + " " + result.graph_path.readable).lower()
    assert "payment_handler.py" in combined_text
    assert "process_payment" in combined_text
    assert "alice smith" in combined_text
    assert "payments on-call primary" in combined_text or "on-call" in combined_text

    # Assert readable path format
    assert "-[:" in result.graph_path.readable
    assert len(result.graph_path.nodes) >= 4
    assert len(result.tool_calls) >= 1
