"""A bounded loop for dispatching mock-model tool calls."""

from __future__ import annotations

import json
from typing import Any, Callable

from .firewall import CordonFirewall, FirewallDecision
from .llm import MockLLM
from .tools import FakeTools


class ToolLoopLimitError(RuntimeError):
    pass


class ToolLoop:
    def __init__(
        self,
        llm: MockLLM,
        tools: FakeTools,
        max_tool_calls: int = 8,
        firewall: CordonFirewall | None = None,
        approval_handler: Callable[
            [str, dict[str, Any], FirewallDecision], bool
        ]
        | None = None,
    ) -> None:
        if max_tool_calls < 1:
            raise ValueError("max_tool_calls must be at least 1.")
        self.llm = llm
        self.tools = tools
        self.max_tool_calls = max_tool_calls
        self.firewall = firewall
        self.approval_handler = approval_handler
        self.firewall_events: list[tuple[str, Any]] = []

    def run(self, prompt: str) -> str:
        messages: list[dict[str, Any]] = [
            {
                "role": "system",
                "content": (
                    "Review the user's request and use available fake tools "
                    "when appropriate."
                ),
            },
            {"role": "user", "content": prompt},
        ]
        calls_used = 0

        while True:
            turn = self.llm.complete(messages)
            if not turn.tool_calls:
                return turn.content
            if calls_used + len(turn.tool_calls) > self.max_tool_calls:
                raise ToolLoopLimitError(
                    f"Tool loop exceeded {self.max_tool_calls} tool calls."
                )

            messages.append(
                {
                    "role": "assistant",
                    "content": turn.content,
                    "tool_calls": [
                        {
                            "id": call.id,
                            "name": call.name,
                            "arguments": call.arguments,
                        }
                        for call in turn.tool_calls
                    ],
                }
            )
            for call_index, call in enumerate(turn.tool_calls):
                source_id = f"{call.id}:{calls_used + call_index + 1}"
                if self.firewall is None:
                    result = self.tools.execute(call.name, call.arguments)
                else:
                    decision = self.firewall.check(call.name, call.arguments)
                    if decision.rule_id == "R5" and self.approval_handler is not None:
                        approved = self.approval_handler(
                            call.name,
                            call.arguments,
                            decision,
                        )
                        if approved:
                            decision = self.firewall.check(
                                call.name,
                                call.arguments,
                                approved=True,
                            )
                    self.firewall_events.append((call.name, decision))
                    result = (
                        self.tools.execute(call.name, call.arguments)
                        if decision.allowed
                        else json.dumps(
                            {
                                "error": (
                                    f"Blocked by CORDON ({decision.rule_id}): "
                                    f"{decision.reason}"
                                )
                            }
                        )
                    )
                    if decision.allowed:
                        self.firewall.record_tool_output(
                            source_id,
                            call.name,
                            result,
                        )
                messages.append(
                    {
                        "role": "tool",
                        "name": call.name,
                        "tool_call_id": source_id,
                        "content": result,
                    }
                )
            calls_used += len(turn.tool_calls)
