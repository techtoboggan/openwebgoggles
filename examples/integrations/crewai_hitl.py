"""
CrewAI + OpenWebGoggles — Human-in-the-Loop crew with approval gates.

Shows how to add HITL checkpoints to a CrewAI workflow where specific
tasks require human review before the crew proceeds.

Requirements:
    pip install crewai openwebgoggles

Setup:
    openwebgoggles init claude

Usage:
    The crew runs autonomously but pauses at approval gates for human input
    via OpenWebGoggles rich UI panels.
"""

from __future__ import annotations

from crewai import Agent, Crew, Task
from crewai.tools import BaseTool

# ---------------------------------------------------------------------------
# OpenWebGoggles HITL tools for CrewAI
# ---------------------------------------------------------------------------


class HumanApprovalTool(BaseTool):
    """Request human approval via OpenWebGoggles rich UI panel."""

    name: str = "human_approval"
    description: str = (
        "Present a decision to the human for approval or rejection. "
        "Returns the human's decision with optional feedback. "
        "Use before any irreversible action."
    )

    def _run(self, title: str, description: str, details: str = "") -> str:
        """Build an OpenWebGoggles approval state.

        In production, this calls the MCP tool directly.
        Here we show the state construction pattern.
        """
        from openwebgoggles.sdk import confirm

        state = confirm(
            title=title,
            message=description,
            details=details,
        )

        # In MCP context: result = mcp.call_tool("openwebgoggles", state)
        # For demo, return the state that would be passed to the MCP tool
        import json

        return json.dumps(
            {
                "tool": "openwebgoggles",
                "state": state,
                "note": "Pass this state to the openwebgoggles() MCP tool",
            },
            indent=2,
        )


class HumanInputTool(BaseTool):
    """Collect structured input from a human via OpenWebGoggles form."""

    name: str = "human_input"
    description: str = (
        "Show a form to the human and collect structured responses. "
        "Use when you need configuration, preferences, or missing data."
    )

    def _run(self, title: str, questions: str) -> str:
        """Build an OpenWebGoggles form state.

        questions: comma-separated list of field names to ask about.
        """
        from openwebgoggles.sdk import Field, show_form

        fields = [
            Field(key=q.strip(), label=q.strip().replace("_", " ").title(), field_type="text")
            for q in questions.split(",")
        ]
        state = show_form(title=title, fields=fields)

        import json

        return json.dumps(
            {
                "tool": "openwebgoggles",
                "state": state,
                "note": "Pass this state to the openwebgoggles() MCP tool",
            },
            indent=2,
        )


class ShowDashboardTool(BaseTool):
    """Show a live metrics dashboard to the human."""

    name: str = "show_dashboard"
    description: str = (
        "Display a metrics dashboard with key indicators. Use to present results, status updates, or summaries."
    )

    def _run(self, title: str, metrics_json: str) -> str:
        """Build an OpenWebGoggles dashboard state."""
        import json

        from openwebgoggles.sdk import show_dashboard

        metrics = json.loads(metrics_json)
        state = show_dashboard(title=title, metrics=metrics)

        return json.dumps(
            {
                "tool": "openwebgoggles_update",
                "state": state,
                "note": "Pass to openwebgoggles_update() for non-blocking display",
            },
            indent=2,
        )


# ---------------------------------------------------------------------------
# Crew definition
# ---------------------------------------------------------------------------


def create_deployment_crew() -> Crew:
    """Create a CrewAI crew with HITL approval gates."""

    # Tools
    approval_tool = HumanApprovalTool()
    input_tool = HumanInputTool()
    dashboard_tool = ShowDashboardTool()

    # Agents
    planner = Agent(
        role="Deployment Planner",
        goal="Plan safe, well-documented deployments",
        backstory=(
            "You are a senior SRE who plans deployments carefully. "
            "You always check with humans before proceeding with anything risky."
        ),
        tools=[input_tool],
        verbose=True,
    )

    executor = Agent(
        role="Deployment Executor",
        goal="Execute deployments safely with human oversight",
        backstory=(
            "You execute deployment plans but ALWAYS get human approval before making changes to production systems."
        ),
        tools=[approval_tool, dashboard_tool],
        verbose=True,
    )

    reviewer = Agent(
        role="Post-Deploy Reviewer",
        goal="Verify deployment success and report metrics",
        backstory=("You monitor deployments after completion and present results to the human for sign-off."),
        tools=[dashboard_tool, approval_tool],
        verbose=True,
    )

    # Tasks
    plan_task = Task(
        description=(
            "Plan the deployment of {service} version {version}. "
            "Ask the human for any missing configuration using the human_input tool. "
            "Output a step-by-step deployment plan."
        ),
        expected_output="A detailed deployment plan with steps and rollback strategy.",
        agent=planner,
    )

    deploy_task = Task(
        description=(
            "Execute the deployment plan. Before each step, use human_approval "
            "to get explicit permission. Show progress via show_dashboard."
        ),
        expected_output="Deployment completion status with any issues encountered.",
        agent=executor,
    )

    review_task = Task(
        description=(
            "After deployment, check health metrics and present a summary "
            "dashboard to the human. Get their sign-off using human_approval."
        ),
        expected_output="Post-deployment health report with human sign-off.",
        agent=reviewer,
    )

    return Crew(
        agents=[planner, executor, reviewer],
        tasks=[plan_task, deploy_task, review_task],
        verbose=True,
    )


# ---------------------------------------------------------------------------
# Example usage
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    crew = create_deployment_crew()
    result = crew.kickoff(
        inputs={
            "service": "auth-service",
            "version": "2.3.1",
        }
    )
    print(result)
