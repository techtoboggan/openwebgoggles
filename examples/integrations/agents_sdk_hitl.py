"""
Anthropic Agents SDK + OpenWebGoggles — HITL agent with native MCP.

This is the most natural integration since both OpenWebGoggles and
Agents SDK use MCP natively. The agent discovers OpenWebGoggles tools
automatically via MCP and uses them for human interaction.

Requirements:
    pip install agents openwebgoggles

Setup:
    openwebgoggles init claude

Usage:
    The Agents SDK connects to the OpenWebGoggles MCP server and
    exposes its tools (openwebgoggles, openwebgoggles_update, etc.)
    directly to the agent.
"""

from __future__ import annotations

import asyncio
from typing import Any

from agents import Agent, Runner
from agents.mcp import MCPServerStdio

# ---------------------------------------------------------------------------
# MCP Server connection
# ---------------------------------------------------------------------------


def create_owg_server() -> MCPServerStdio:
    """Create an MCP server connection to OpenWebGoggles.

    The Agents SDK discovers all OWG tools automatically:
    - openwebgoggles (show UI + wait for response)
    - openwebgoggles_update (push live updates)
    - openwebgoggles_read (poll for actions)
    - openwebgoggles_close (end session)
    - openwebgoggles_save / openwebgoggles_restore (persistence)
    """
    return MCPServerStdio(
        name="openwebgoggles",
        # The binary path — 'openwebgoggles' if installed via pipx,
        # or the full path from 'which openwebgoggles'
        command="openwebgoggles",
        args=[],
    )


# ---------------------------------------------------------------------------
# Agent definitions
# ---------------------------------------------------------------------------

# The agent's instructions tell it WHEN to use OWG tools.
# The SDK handles HOW (tool discovery, invocation, response parsing).

DEPLOYMENT_AGENT_INSTRUCTIONS = """\
You are a deployment automation agent. You help teams deploy services
safely with human oversight.

## When to use OpenWebGoggles tools:

1. **Before destructive actions** → use `openwebgoggles` with a confirmation state:
   ```json
   {
     "title": "Deploy auth-service v2.3.1",
     "message": "This will deploy to production. Changes cannot be undone.",
     "preset": "confirm"
   }
   ```

2. **To collect configuration** → use `openwebgoggles` with a form:
   ```json
   {
     "title": "Deployment Config",
     "data": {
       "sections": [{
         "type": "form",
         "title": "Settings",
         "fields": [
           {"key": "env", "label": "Environment", "type": "select",
            "options": ["staging", "production"]},
           {"key": "replicas", "label": "Replicas", "type": "number",
            "value": 3, "min": 1, "max": 10}
         ]
       }]
     },
     "actions_requested": [
       {"id": "submit", "label": "Deploy", "type": "approve"},
       {"id": "cancel", "label": "Cancel", "type": "reject"}
     ]
   }
   ```

3. **During long operations** → use `openwebgoggles_update` with progress:
   ```json
   {
     "title": "Deploying...",
     "data": {
       "sections": [{
         "type": "progress",
         "tasks": [
           {"label": "Pull image", "status": "complete"},
           {"label": "Run migrations", "status": "running"},
           {"label": "Swap traffic", "status": "pending"}
         ],
         "percentage": 45
       }]
     }
   }
   ```

4. **To show results** → use `openwebgoggles_update` with a dashboard:
   ```json
   {
     "title": "Deployment Complete",
     "preset": "dashboard",
     "data": {
       "metrics": [
         {"label": "Response Time", "value": "142ms", "delta": "-18ms"},
         {"label": "Error Rate", "value": "0.02%", "delta": "-0.01%"}
       ]
     }
   }
   ```

5. **When done** → use `openwebgoggles_close` with a summary message.

## Rules:
- NEVER skip the approval step for production deployments
- Always show progress during multi-step operations
- Present results in a dashboard, not raw text
- If the human rejects, explain why and offer alternatives
"""

TRIAGE_AGENT_INSTRUCTIONS = """\
You are a bug triage agent. You review incoming issues and present them
to a human for classification and prioritization.

## OpenWebGoggles patterns:

1. **Batch triage** → use `openwebgoggles` with a table:
   ```json
   {
     "title": "Bug Triage",
     "data": {
       "sections": [{
         "type": "table",
         "title": "Unclassified Issues",
         "clickable": true,
         "columns": [
           {"key": "id", "label": "ID"},
           {"key": "title", "label": "Title"},
           {"key": "severity", "label": "Severity"}
         ],
         "rows": [...]
       }]
     },
     "actions_requested": [
       {"id": "classify", "label": "Classify Selected", "type": "primary"},
       {"id": "skip", "label": "Skip All", "type": "ghost"}
     ]
   }
   ```

2. **Per-issue review** → use multi-session for parallel reviews:
   ```json
   {
     "title": "Review: AUTH-1234",
     "session_name": "triage-AUTH-1234",
     ...
   }
   ```
"""


# ---------------------------------------------------------------------------
# Agent creation
# ---------------------------------------------------------------------------


async def run_deployment_agent(task: str) -> str:
    """Run the deployment agent with OWG HITL integration."""
    owg = create_owg_server()

    agent = Agent(
        name="deployment-agent",
        instructions=DEPLOYMENT_AGENT_INSTRUCTIONS,
        mcp_servers=[owg],
    )

    result = await Runner.run(agent, task)
    return result.final_output


async def run_triage_agent(issues: list[dict[str, Any]]) -> str:
    """Run the triage agent to classify issues with human input."""
    owg = create_owg_server()

    agent = Agent(
        name="triage-agent",
        instructions=TRIAGE_AGENT_INSTRUCTIONS,
        mcp_servers=[owg],
    )

    task = f"Triage these {len(issues)} issues. Present them to the human for classification:\n\n" + "\n".join(
        f"- {i['id']}: {i['title']}" for i in issues
    )

    result = await Runner.run(agent, task)
    return result.final_output


# ---------------------------------------------------------------------------
# Multi-agent handoff example
# ---------------------------------------------------------------------------

COORDINATOR_INSTRUCTIONS = """\
You coordinate between specialized agents. You have access to:
- deployment-agent: handles deployments with human approval
- triage-agent: classifies bugs with human review

Route tasks to the appropriate agent. Use OpenWebGoggles to show
the human which agent is working and what it's doing.
"""


async def run_coordinator(task: str) -> str:
    """Run a multi-agent system where each agent uses OWG for HITL."""
    owg = create_owg_server()

    deploy_agent = Agent(
        name="deployment-agent",
        instructions=DEPLOYMENT_AGENT_INSTRUCTIONS,
        mcp_servers=[owg],
    )

    triage_agent = Agent(
        name="triage-agent",
        instructions=TRIAGE_AGENT_INSTRUCTIONS,
        mcp_servers=[owg],
    )

    coordinator = Agent(
        name="coordinator",
        instructions=COORDINATOR_INSTRUCTIONS,
        mcp_servers=[owg],
        handoffs=[deploy_agent, triage_agent],
    )

    result = await Runner.run(coordinator, task)
    return result.final_output


# ---------------------------------------------------------------------------
# Example usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # Single agent
    output = asyncio.run(
        run_deployment_agent("Deploy auth-service v2.3.1 to production. Show me the current metrics first.")
    )
    print(output)

    # Multi-agent coordinator
    output = asyncio.run(run_coordinator("First triage the open bugs, then deploy the fix for the critical one."))
    print(output)
