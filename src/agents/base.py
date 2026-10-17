"""BaseAgent foundation providing tool registration, LLM invocation, and graph path enforcement."""

import json
from datetime import datetime, timezone
from typing import Any, Callable, Dict, List, Optional
import requests

from src.config import Settings, get_settings
from src.models import AgentResult, GraphPath, ToolCallRecord


class ToolDescriptor:
    """Descriptor combining a callable tool with its schema documentation."""

    def __init__(self, name: str, func: Callable, description: str, parameters: Dict[str, Any]) -> None:
        """Initialize the tool descriptor with execution function and JSON schema."""
        self.name = name
        self.func = func
        self.description = description
        self.parameters = parameters

    def to_openai_tool(self) -> Dict[str, Any]:
        """Convert descriptor to OpenAI function calling tool definition format."""
        return {
            "type": "function",
            "function": {
                "name": self.name,
                "description": self.description,
                "parameters": self.parameters,
            },
        }


class BaseAgent:
    """Base autonomous agent executing multi-step reasoning with graph tool calls."""

    def __init__(
        self,
        name: str,
        system_prompt: str = "",
        settings: Optional[Settings] = None,
        llm_client: Optional[Callable[[List[Dict[str, Any]], List[Dict[str, Any]]], Dict[str, Any]]] = None,
    ) -> None:
        """Initialize the agent with tool registry and LLM execution client."""
        self.name = name
        self.settings = settings or get_settings()
        self.tools: Dict[str, ToolDescriptor] = {}
        self.llm_client = llm_client or self._default_llm_client
        self.system_prompt = system_prompt or (
            f"You are {self.name}, an autonomous security incident agent. "
            "You MUST use graph tools to inspect the architecture and ground every decision. "
            "Every final response MUST be accompanied by a Cypher-derived graph path."
        )

    def register_tool(
        self, name: str, func: Callable, description: str, parameters: Dict[str, Any]
    ) -> None:
        """Register a query or action tool with parameter schema into the agent registry."""
        self.tools[name] = ToolDescriptor(name, func, description, parameters)

    def _default_llm_client(
        self, messages: List[Dict[str, Any]], tools: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Send chat messages and tool specifications to the configured LLM endpoint."""
        url = f"{self.settings.llm_base_url.rstrip('/')}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.settings.llm_api_key}",
            "Content-Type": "application/json",
        }
        payload: Dict[str, Any] = {
            "model": self.settings.llm_model,
            "messages": messages,
            "temperature": 0.0,
        }
        if tools:
            payload["tools"] = tools
            payload["tool_choice"] = "auto"

        response = requests.post(url, headers=headers, json=payload, timeout=30)
        response.raise_for_status()
        data = response.json()
        choice = data.get("choices", [{}])[0]
        return choice.get("message", {})

    def _execute_tool(self, tool_name: str, args: Dict[str, Any]) -> tuple[Any, str, Optional[GraphPath]]:
        """Invoke a registered tool function and extract any returned GraphPath."""
        if tool_name not in self.tools:
            return None, f"Error: Tool '{tool_name}' not found", None

        try:
            raw_res = self.tools[tool_name].func(**args)
            extracted_path: Optional[GraphPath] = None

            if isinstance(raw_res, list) and raw_res and hasattr(raw_res[0], "path"):
                if isinstance(raw_res[0].path, GraphPath):
                    extracted_path = raw_res[0].path
            elif hasattr(raw_res, "path") and isinstance(raw_res.path, GraphPath):
                extracted_path = raw_res.path
            elif isinstance(raw_res, GraphPath):
                extracted_path = raw_res

            summary = str(raw_res)[:300]
            return raw_res, summary, extracted_path
        except Exception as exc:
            return None, f"Execution failed: {exc}", None

    def run(self, task: str, context: Optional[Dict[str, Any]] = None, max_iterations: int = 5) -> AgentResult:
        """Execute agent reasoning loop, invoke tools, and enforce graph-path grounding."""
        ctx = context or {}
        messages: List[Dict[str, Any]] = [
            {"role": "system", "content": self.system_prompt},
            {
                "role": "user",
                "content": f"Task: {task}\nContext: {json.dumps(ctx, default=str)}",
            },
        ]
        tool_defs = [td.to_openai_tool() for td in self.tools.values()]
        logged_calls: List[Dict[str, Any]] = []
        observed_graph_path: Optional[GraphPath] = None

        for _ in range(max_iterations):
            msg = self.llm_client(messages, tool_defs)
            messages.append(msg)

            tool_calls = msg.get("tool_calls", [])
            content = msg.get("content") or ""

            # Fallback parsing for strict JSON-in-text responses
            if not tool_calls and content.strip().startswith("{") and "tool" in content:
                try:
                    parsed = json.loads(content)
                    if "tool" in parsed:
                        tool_calls = [{
                            "id": "json_call",
                            "function": {
                                "name": parsed["tool"],
                                "arguments": json.dumps(parsed.get("args", {})),
                            },
                        }]
                except Exception:
                    pass

            if not tool_calls:
                # LLM finished reasoning and returned final answer
                # Try parsing content if it returned JSON with graph_path
                final_answer = content
                if content.strip().startswith("{"):
                    try:
                        p = json.loads(content)
                        if "answer" in p:
                            final_answer = p["answer"]
                        if "graph_path" in p and isinstance(p["graph_path"], dict):
                            observed_graph_path = GraphPath(**p["graph_path"])
                    except Exception:
                        pass

                # Enforce graph path justification rule
                if observed_graph_path is None:
                    return AgentResult(
                        success=False,
                        answer="Error: Decision rejected. No Cypher-derived graph path provided to justify response.",
                        graph_path=None,
                        tool_calls=logged_calls,
                        raw={"final_content": content, "error": "NO_GRAPH_PATH_JUSTIFICATION"},
                    )

                return AgentResult(
                    success=True,
                    answer=final_answer,
                    graph_path=observed_graph_path,
                    tool_calls=logged_calls,
                    raw={"final_message": msg},
                )

            # Process tool calls
            for tc in tool_calls:
                fn = tc.get("function", {})
                name = fn.get("name", "")
                raw_args = fn.get("arguments", "{}")
                args = json.loads(raw_args) if isinstance(raw_args, str) else raw_args

                res_obj, res_summary, gpath = self._execute_tool(name, args)
                if gpath is not None:
                    observed_graph_path = gpath

                record = ToolCallRecord(
                    name=name,
                    args=args,
                    result_summary=res_summary,
                    timestamp=datetime.now(timezone.utc).isoformat(),
                )
                logged_calls.append(record.model_dump())

                messages.append({
                    "role": "tool",
                    "tool_call_id": tc.get("id", "call_id"),
                    "name": name,
                    "content": json.dumps(res_obj, default=str),
                })

        # Loop limit reached without definitive grounded answer
        if observed_graph_path is None:
            return AgentResult(
                success=False,
                answer="Error: Agent exceeded maximum iterations without verifying a valid graph path.",
                graph_path=None,
                tool_calls=logged_calls,
                raw={"status": "MAX_ITERATIONS_EXCEEDED"},
            )

        return AgentResult(
            success=True,
            answer=messages[-1].get("content") or "Agent completed reasoning loop.",
            graph_path=observed_graph_path,
            tool_calls=logged_calls,
            raw={"status": "COMPLETED_ON_MAX_ITERATIONS"},
        )
