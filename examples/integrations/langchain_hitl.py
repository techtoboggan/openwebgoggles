"""
LangChain + OpenWebGoggles — Human-in-the-Loop agent with rich UI.

Shows how to add HITL approval gates, form inputs, and live progress
dashboards to a LangChain agent using OpenWebGoggles MCP tools.

Requirements:
    pip install langchain langchain-anthropic openwebgoggles

Setup:
    openwebgoggles init claude   # or your editor

Usage:
    Run this as an MCP tool inside Claude Code or any MCP-capable host.
    The agent will use OpenWebGoggles for human interaction.
"""

from __future__ import annotations

from typing import Any

from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain.tools import StructuredTool
from langchain_anthropic import ChatAnthropic

# ---------------------------------------------------------------------------
# OpenWebGoggles HITL tools (wrapping MCP calls for LangChain)
# ---------------------------------------------------------------------------

# In a real setup, these call the MCP tools via the host.
# This example shows the pattern — adapt to your MCP client.


def ask_human_approval(
    title: str,
    message: str,
    details: str | None = None,
) -> dict[str, Any]:
    """Show an approval dialog and wait for the human's decision.

    Returns {"approved": True/False, "feedback": "..."}.
    """
    from openwebgoggles.sdk import confirm

    state = confirm(
        title=title,
        message=message,
        details=details,
    )
    # In MCP context, this becomes: mcp.call_tool("openwebgoggles", state)
    # For demonstration, we show the state structure:
    return {
        "state": state,
        "description": "Pass this state to the openwebgoggles() MCP tool",
    }


def ask_human_form(
    title: str,
    fields: list[dict[str, Any]],
    message: str = "",
) -> dict[str, Any]:
    """Show a form and collect structured input from the human.

    Returns {"values": {"field_key": "value", ...}}.
    """
    from openwebgoggles.sdk import Field, show_form

    sdk_fields = [
        Field(
            key=f["key"],
            label=f.get("label", f["key"]),
            field_type=f.get("type", "text"),
            required=f.get("required", False),
            placeholder=f.get("placeholder", ""),
            options=f.get("options"),
        )
        for f in fields
    ]
    state = show_form(title=title, fields=sdk_fields, message=message)
    return {
        "state": state,
        "description": "Pass this state to the openwebgoggles() MCP tool",
    }


def show_progress_dashboard(
    title: str,
    tasks: list[dict[str, str]],
    percentage: int = 0,
) -> dict[str, Any]:
    """Show a non-blocking progress dashboard.

    Each task: {"label": "Step name", "status": "complete|running|pending"}
    """
    from openwebgoggles.sdk import show_progress

    state = show_progress(title=title, tasks=tasks, percentage=percentage)
    return {
        "state": state,
        "description": "Pass this state to openwebgoggles_update() for live updates",
    }


# ---------------------------------------------------------------------------
# LangChain tool definitions
# ---------------------------------------------------------------------------

approval_tool = StructuredTool.from_function(
    func=ask_human_approval,
    name="ask_human_approval",
    description=(
        "Show a rich approval dialog to the human. "
        "Use when the agent needs permission before proceeding with a "
        "destructive or irreversible action."
    ),
)

form_tool = StructuredTool.from_function(
    func=ask_human_form,
    name="ask_human_form",
    description=(
        "Show a form to collect structured input from the human. "
        "Use when the agent needs configuration values, preferences, "
        "or missing information."
    ),
)

progress_tool = StructuredTool.from_function(
    func=show_progress_dashboard,
    name="show_progress",
    description=(
        "Show a non-blocking progress dashboard. Use during long-running operations to keep the human informed."
    ),
)


# ---------------------------------------------------------------------------
# Agent setup
# ---------------------------------------------------------------------------


def create_hitl_agent() -> AgentExecutor:
    """Create a LangChain agent with HITL capabilities via OpenWebGoggles."""
    llm = ChatAnthropic(model="claude-sonnet-4-20250514", temperature=0)

    tools = [approval_tool, form_tool, progress_tool]

    # System prompt that teaches the agent when to use HITL
    system_prompt = """\
You are a helpful assistant with access to human-in-the-loop tools.

Guidelines:
- Before any destructive action (delete, deploy, publish), use ask_human_approval
- When you need configuration or preferences, use ask_human_form
- During multi-step operations, use show_progress to keep the human informed
- Always respect the human's decision — if they reject, explain and offer alternatives
"""

    agent = create_tool_calling_agent(llm, tools, system_prompt)
    return AgentExecutor(agent=agent, tools=tools, verbose=True)


# ---------------------------------------------------------------------------
# Example usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    agent = create_hitl_agent()

    # Example: Agent asks for deployment approval
    result = agent.invoke(
        {"input": ("Deploy the auth-service v2.3.1 to production. It changes the token expiry from 1h to 24h.")}
    )
    print(result["output"])
