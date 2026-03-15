# Agent Framework Integrations

OpenWebGoggles provides human-in-the-loop (HITL) capabilities to any agent framework via MCP tools. This guide covers integration patterns for the most popular frameworks.

## Quick Comparison

| Framework | Integration Style | Complexity | Best For |
|-----------|------------------|------------|----------|
| **Agents SDK** | Native MCP — zero glue code | ⭐ Simplest | Anthropic-native agents |
| **LangChain** | `StructuredTool` wrappers | ⭐⭐ Low | Tool-calling chains |
| **CrewAI** | `BaseTool` subclasses | ⭐⭐ Low | Multi-agent crews |
| **AutoGen** | `UserProxyAgent` override | ⭐⭐⭐ Medium | Conversational agents |

---

## Anthropic Agents SDK

The most natural integration — both use MCP natively.

### Setup

```bash
pip install agents openwebgoggles
openwebgoggles init claude
```

### Usage

The Agents SDK discovers OpenWebGoggles tools automatically:

```python
from agents import Agent, Runner
from agents.mcp import MCPServerStdio

owg = MCPServerStdio(
    name="openwebgoggles",
    command="openwebgoggles",
)

agent = Agent(
    name="deploy-bot",
    instructions="Before deploying, use openwebgoggles with preset='confirm'...",
    mcp_servers=[owg],
)

result = await Runner.run(agent, "Deploy auth-service v2.3.1")
```

### Key Patterns

**Approval gate** — the agent uses `openwebgoggles` with `preset="confirm"`:

```python
# The agent's instructions tell it to call the MCP tool:
# openwebgoggles(state={"title": "Deploy?", "preset": "confirm"})
# The tool blocks until the human approves or rejects.
```

**Live progress** — the agent streams updates via `openwebgoggles_update`:

```python
# Agent calls openwebgoggles_update with progress sections
# while performing long-running work. Non-blocking.
```

**Multi-agent handoff** — each agent shares the same OWG MCP server:

```python
coordinator = Agent(
    name="coordinator",
    mcp_servers=[owg],
    handoffs=[deploy_agent, triage_agent],
)
```

**Multi-session** — parallel agents each get their own UI panel:

```python
# Agent 1: openwebgoggles(state={...}, session="deploy-auth")
# Agent 2: openwebgoggles(state={...}, session="deploy-api")
```

→ Full example: [`examples/integrations/agents_sdk_hitl.py`](../examples/integrations/agents_sdk_hitl.py)

---

## LangChain

Wrap OpenWebGoggles SDK helpers as `StructuredTool` instances.

### Setup

```bash
pip install langchain langchain-anthropic openwebgoggles
openwebgoggles init claude
```

### Tool Definition Pattern

```python
from langchain.tools import StructuredTool
from openwebgoggles.sdk import confirm, was_confirmed

def ask_approval(title: str, message: str) -> dict:
    state = confirm(title=title, message=message)
    result = mcp.call_tool("openwebgoggles", state)
    return {"approved": was_confirmed(result)}

approval_tool = StructuredTool.from_function(
    func=ask_approval,
    name="ask_human_approval",
    description="Request human approval before destructive actions.",
)
```

### Agent Setup

```python
from langchain.agents import AgentExecutor, create_tool_calling_agent
from langchain_anthropic import ChatAnthropic

llm = ChatAnthropic(model="claude-sonnet-4-20250514")
tools = [approval_tool, form_tool, progress_tool]
agent = create_tool_calling_agent(llm, tools, system_prompt)
executor = AgentExecutor(agent=agent, tools=tools)

result = executor.invoke({"input": "Deploy auth-service v2.3.1"})
```

### Available SDK Helpers

| Helper | Use Case | LangChain Tool Name |
|--------|----------|-------------------|
| `confirm()` | Approval gates | `ask_human_approval` |
| `show_form()` | Collect input | `ask_human_form` |
| `show_table()` | Display data | `show_data_table` |
| `show_progress()` | Live progress | `show_progress` |
| `show_dashboard()` | Metrics display | `show_dashboard` |
| `show_diff()` | Code review | `show_code_diff` |
| `show_chart()` | Visualizations | `show_chart` |

→ Full example: [`examples/integrations/langchain_hitl.py`](../examples/integrations/langchain_hitl.py)

---

## CrewAI

Subclass `BaseTool` to create HITL checkpoints in crew workflows.

### Setup

```bash
pip install crewai openwebgoggles
openwebgoggles init claude
```

### Tool Definition Pattern

```python
from crewai.tools import BaseTool
from openwebgoggles.sdk import confirm

class HumanApprovalTool(BaseTool):
    name: str = "human_approval"
    description: str = "Present a decision to the human for approval."

    def _run(self, title: str, description: str) -> str:
        state = confirm(title=title, message=description)
        result = mcp.call_tool("openwebgoggles", state)
        return "APPROVED" if was_confirmed(result) else "REJECTED"
```

### Crew with HITL Gates

```python
from crewai import Agent, Crew, Task

executor = Agent(
    role="Deployment Executor",
    goal="Execute deployments with human oversight",
    tools=[HumanApprovalTool(), ShowDashboardTool()],
)

deploy_task = Task(
    description="Deploy {service}. Use human_approval before each step.",
    agent=executor,
)

crew = Crew(agents=[executor], tasks=[deploy_task])
result = crew.kickoff(inputs={"service": "auth-service"})
```

### Pattern: Sequential Approval Chain

```
Planner (collects config via OWG form)
    → Executor (approval gate at each step)
        → Reviewer (dashboard + final sign-off)
```

Each agent uses different OWG tools:
- **Planner**: `show_form()` → collect deployment config
- **Executor**: `confirm()` → gate each step, `show_progress()` → live updates
- **Reviewer**: `show_dashboard()` → metrics, `confirm()` → final sign-off

→ Full example: [`examples/integrations/crewai_hitl.py`](../examples/integrations/crewai_hitl.py)

---

## AutoGen

Override `UserProxyAgent.get_human_input()` to route through OpenWebGoggles.

### Setup

```bash
pip install autogen-agentchat openwebgoggles
openwebgoggles init claude
```

### UserProxy Override

```python
from autogen import UserProxyAgent
from openwebgoggles.sdk import confirm, show_form, Field

class OWGUserProxy(UserProxyAgent):
    def get_human_input(self, prompt: str) -> str:
        # Detect intent and pick appropriate UI
        if "approve" in prompt.lower():
            state = confirm("Agent Needs Approval", prompt)
        else:
            state = show_form("Agent Question", [
                Field("response", "Your Response", "textarea"),
            ], message=prompt)

        result = mcp.call_tool("openwebgoggles", state)
        return extract_response(result)
```

### Function Tools with HITL

```python
def deploy_service(service: str, version: str, env: str) -> str:
    # Show approval panel
    state = confirm(f"Deploy {service} {version}", f"Target: {env}")
    result = mcp.call_tool("openwebgoggles", state)
    if not was_confirmed(result):
        return "Deployment cancelled."

    # Show progress
    progress = show_progress("Deploying...", tasks=[...])
    mcp.call_tool("openwebgoggles_update", progress)

    return "Deployed successfully."

user = OWGUserProxy(
    name="human",
    function_map={"deploy_service": deploy_service},
)
```

→ Full example: [`examples/integrations/autogen_hitl.py`](../examples/integrations/autogen_hitl.py)

---

## Common Patterns

### 1. Approval Gate

The most common pattern — block until a human approves or rejects.

```python
from openwebgoggles.sdk import confirm, was_confirmed

state = confirm(
    title="Deploy to Production",
    message="This will deploy auth-service v2.3.1.",
    details="Changes:\n- Token expiry: 1h → 24h\n- New /refresh endpoint",
)
result = mcp.call_tool("openwebgoggles", {"state": state})

if was_confirmed(result):
    deploy()
else:
    rollback()
```

### 2. Multi-Step Wizard

Collect information across multiple screens.

```python
from openwebgoggles.sdk import show_form, Field, get_form_values

# Step 1: Environment
state = show_form("Step 1: Environment", [
    Field("env", "Target", "select", options=["staging", "production"]),
])
result = mcp.call_tool("openwebgoggles", {"state": state})
env = get_form_values(result)["env"]

# Step 2: Configuration
state = show_form("Step 2: Config", [
    Field("replicas", "Replicas", "number", value=3, min_value=1, max_value=10),
    Field("notify", "Notify team", "checkbox", value=True),
])
result = mcp.call_tool("openwebgoggles", {"state": state})
config = get_form_values(result)
```

### 3. Live Dashboard

Non-blocking updates during long operations.

```python
from openwebgoggles.sdk import show_progress, show_dashboard

# Initial display
state = show_progress("Building", [
    {"label": "Compile", "status": "running"},
    {"label": "Test", "status": "pending"},
    {"label": "Package", "status": "pending"},
], percentage=10)
mcp.call_tool("openwebgoggles", {"state": state})

# Update as work progresses (non-blocking)
for step, pct in [("Compile", 40), ("Test", 70), ("Package", 100)]:
    updated = show_progress("Building", [
        {"label": "Compile", "status": "complete" if pct > 40 else "running"},
        {"label": "Test", "status": "complete" if pct > 70 else ("running" if pct > 40 else "pending")},
        {"label": "Package", "status": "complete" if pct >= 100 else ("running" if pct > 70 else "pending")},
    ], percentage=pct)
    mcp.call_tool("openwebgoggles_update", {"state": updated, "merge": True})
```

### 4. Parallel Reviews (Multi-Session)

Multiple HITL panels for independent decisions.

```python
# Each review gets its own panel
for pr in pull_requests:
    state = show_diff(
        title=f"Review: {pr.title}",
        content=pr.diff,
    )
    mcp.call_tool("openwebgoggles", {
        "state": state,
        "session": f"review-{pr.id}",
    })

# Poll all sessions
for pr in pull_requests:
    result = mcp.call_tool("openwebgoggles_read", {
        "session": f"review-{pr.id}",
    })
```

### 5. Webhook Notifications

Get notified when an agent is waiting for input.

```bash
# Set before starting the MCP server
export OWG_WEBHOOK_URL="https://hooks.slack.com/services/T00/B00/xxx"

# Optional: custom message template
export OWG_WEBHOOK_TEMPLATE="🔔 {title} — {status} — {url}"
```

Supports Slack, Discord, and generic HTTP webhooks. See [Webhook Docs](../README.md#webhook-notifications).

---

## Framework-Specific Tips

### Agents SDK
- **Zero glue code** — just point `MCPServerStdio` at `openwebgoggles` and the agent discovers all tools
- Use `handoffs` for multi-agent workflows where each agent uses OWG independently
- The agent's `instructions` are the only configuration needed

### LangChain
- Wrap each OWG SDK helper as a separate `StructuredTool`
- Use `AgentExecutor(handle_parsing_errors=True)` for robustness
- For streaming, use `openwebgoggles_update` in a `CallbackHandler`

### CrewAI
- One `BaseTool` subclass per HITL pattern (approval, form, dashboard)
- Use `Task.context` to pass OWG results between tasks
- The `verbose=True` flag shows when agents hit HITL gates

### AutoGen
- Override `get_human_input()` for conversational HITL
- Register OWG-gated functions in `function_map` for tool-based HITL
- Use `human_input_mode="TERMINATE"` to only gate final decisions
