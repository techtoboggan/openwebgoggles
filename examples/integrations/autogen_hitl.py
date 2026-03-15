"""
AutoGen + OpenWebGoggles — Human-in-the-Loop multi-agent conversation.

Shows how to integrate OpenWebGoggles as a rich UI proxy for human input
in AutoGen's conversational agent framework.

Requirements:
    pip install autogen-agentchat openwebgoggles

Setup:
    openwebgoggles init claude

Usage:
    The UserProxy agent routes human input through OpenWebGoggles panels
    instead of plain terminal prompts.
"""

from __future__ import annotations

import json
from typing import Any

from autogen import AssistantAgent, UserProxyAgent, config_list_from_json

# ---------------------------------------------------------------------------
# OpenWebGoggles-backed UserProxy
# ---------------------------------------------------------------------------


class OWGUserProxy(UserProxyAgent):
    """UserProxy that collects human input via OpenWebGoggles rich UI.

    Instead of reading from stdin, this proxy shows an OpenWebGoggles
    panel with context-appropriate UI (approval dialog, form, or
    free-text input) and waits for the human to respond.
    """

    def get_human_input(self, prompt: str) -> str:
        """Override to route input through OpenWebGoggles.

        In production, this calls the MCP tool. Here we show the pattern.
        """
        from openwebgoggles.sdk import Field, confirm, show_form

        # Detect intent from the prompt to pick the right UI
        prompt_lower = prompt.lower()

        if any(word in prompt_lower for word in ("approve", "confirm", "proceed", "deploy")):
            # Approval dialog
            state = confirm(
                title="Agent Needs Approval",
                message=prompt,
            )
            # result = mcp.call_tool("openwebgoggles", state)
            # return "APPROVE" if was_confirmed(result) else "REJECT"
            return _demo_mcp_call("openwebgoggles", state)

        if any(word in prompt_lower for word in ("provide", "enter", "input", "specify")):
            # Free-text form
            state = show_form(
                title="Agent Needs Input",
                fields=[
                    Field("response", "Your Response", "textarea", placeholder="Type here..."),
                ],
                message=prompt,
            )
            # result = mcp.call_tool("openwebgoggles", state)
            # values = get_form_values(result)
            # return values.get("response", "")
            return _demo_mcp_call("openwebgoggles", state)

        # Default: generic text input
        state = show_form(
            title="Agent Question",
            fields=[
                Field("answer", "Your Answer", "text"),
            ],
            message=prompt,
        )
        return _demo_mcp_call("openwebgoggles", state)


def _demo_mcp_call(tool: str, state: dict[str, Any]) -> str:
    """Placeholder — in production, call the MCP tool via host."""
    return json.dumps(
        {
            "tool": tool,
            "state": state,
            "note": "Pass this to the MCP tool. The result contains the human's response.",
        },
        indent=2,
    )


# ---------------------------------------------------------------------------
# Function tools with HITL gates
# ---------------------------------------------------------------------------


def deploy_service(service: str, version: str, environment: str) -> str:
    """Deploy a service (requires human approval via OpenWebGoggles).

    This function is registered as an AutoGen tool. Before executing,
    it shows an approval panel to the human.
    """
    from openwebgoggles.sdk import confirm, show_progress

    # Step 1: Show approval dialog
    approval_state = confirm(  # noqa: F841
        title=f"Deploy {service} {version}",
        message=f"Deploy **{service}** version **{version}** to **{environment}**?",
        details=(
            f"Service: {service}\nVersion: {version}\nEnvironment: {environment}\n\nThis action cannot be undone."
        ),
    )
    # In MCP: result = mcp.call_tool("openwebgoggles", approval_state)
    # if not was_confirmed(result): return "Deployment cancelled by human."

    # Step 2: Show progress (non-blocking)
    progress_state = show_progress(  # noqa: F841
        title=f"Deploying {service} {version}",
        tasks=[
            {"label": "Pull image", "status": "running"},
            {"label": "Run migrations", "status": "pending"},
            {"label": "Swap traffic", "status": "pending"},
            {"label": "Health check", "status": "pending"},
        ],
        percentage=10,
    )
    # In MCP: mcp.call_tool("openwebgoggles_update", progress_state)

    return f"Deployment of {service} {version} to {environment} initiated."


def query_database(query: str) -> str:
    """Execute a database query (shows query to human for review first)."""
    from openwebgoggles.sdk import show_diff

    review_state = show_diff(  # noqa: F841
        title="Review SQL Query",
        content=query,
        message="The agent wants to run this query. Approve or reject.",
    )
    # In MCP: result = mcp.call_tool("openwebgoggles", review_state)
    return f"Query reviewed and executed: {query[:50]}..."


# ---------------------------------------------------------------------------
# Multi-agent conversation setup
# ---------------------------------------------------------------------------


def create_hitl_conversation() -> tuple[OWGUserProxy, AssistantAgent]:
    """Set up an AutoGen conversation with OWG-backed human input."""

    config_list = config_list_from_json(
        env_or_file="OAI_CONFIG_LIST",
        filter_dict={"model": ["claude-sonnet-4-20250514"]},
    )

    # Human proxy with OpenWebGoggles UI
    user = OWGUserProxy(
        name="human",
        human_input_mode="ALWAYS",  # Always route through OWG
        code_execution_config=False,
        function_map={
            "deploy_service": deploy_service,
            "query_database": query_database,
        },
    )

    # Assistant agent
    assistant = AssistantAgent(
        name="devops_agent",
        system_message="""\
You are a DevOps assistant. You help with deployments, database operations,
and infrastructure tasks.

IMPORTANT: Always use the appropriate function to interact with systems.
The human will review and approve each action through a rich UI panel.
Never bypass the approval process.
""",
        llm_config={"config_list": config_list},
    )

    return user, assistant


# ---------------------------------------------------------------------------
# Example usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    user, assistant = create_hitl_conversation()
    user.initiate_chat(
        assistant,
        message="Deploy auth-service v2.3.1 to staging, then run the migration query.",
    )
