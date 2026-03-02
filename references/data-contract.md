# Data Contract Reference

All files live in `.openwebgoggles/` within the current working directory.

## manifest.json

Session metadata. Written by `start_webview.sh`, read by server and SDK.

| Field | Type | Description |
|-------|------|-------------|
| `version` | string | Contract version (`"1.0"`) |
| `app.name` | string | App identifier (e.g., `"approval-review"`) |
| `app.entry` | string | Entry HTML path relative to `apps/` |
| `app.title` | string | Browser tab title |
| `session.id` | string | UUID for this session |
| `session.created_at` | string | ISO 8601 timestamp |
| `session.token` | string | 32-byte hex session token for auth |
| `session.agent_skill` | string | Name of the skill that launched this webview |
| `server.http_port` | int | HTTP port (default: 18420) |
| `server.ws_port` | int | WebSocket port (default: 18421) |
| `server.host` | string | Bind address (default: `"127.0.0.1"`) |

## state.json

Agent-to-webview state. Written by the agent via `write_state.sh`, read by the webview via SDK.

| Field | Type | Description |
|-------|------|-------------|
| `version` | int | Monotonically increasing counter (increment on each write) |
| `status` | string | Lifecycle status (see below) |
| `updated_at` | string | ISO 8601 timestamp |
| `title` | string | Human-readable title for the current state |
| `message` | string | Optional description or instructions |
| `message_format` | string | Set to `"markdown"` to render message as markdown |
| `message_className` | string | CSS class(es) to add to the message box |
| `custom_css` | string | Custom CSS string injected as a `<style>` tag (validated; dangerous patterns blocked) |
| `data` | object | Arbitrary app-specific payload containing `{sections: [...]}` |
| `actions_requested` | array | Actions the agent wants the user to perform |
| `pages` | object | Multi-page SPA navigation (see [SPA Pages](#spa-pages)) |
| `activePage` | string | Which page to show initially (must be a key in `pages`) |
| `showNav` | bool | Show page nav bar (default: `true`). Set `false` when using `navigateTo` for all navigation |
| `behaviors` | array | Client-side conditional field rules (see [Behaviors](#behaviors)) |
| `layout` | object | Multi-panel layout (see [Layouts](#layouts)) |
| `panels` | object | Panel content for layouts (see [Layouts](#layouts)) |

### Status Values

| Status | Meaning |
|--------|---------|
| `initializing` | Server starting up |
| `ready` | Webview loaded, waiting for agent data |
| `pending_review` | Agent has data for user to review |
| `waiting_input` | Agent needs user input to continue |
| `processing` | Agent is working on user's response |
| `completed` | Workflow finished |
| `error` | Something went wrong |

### actions_requested Items

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | Unique action identifier (referenced in responses) |
| `type` | string | `approve`, `reject`, `select`, `input`, `confirm`, `custom` |
| `style` | string | Button style override: `primary`, `danger`, `success`, `warning`, `ghost`, `submit` |
| `label` | string | Human-readable button/field label |
| `description` | string | Tooltip or helper text |
| `options` | array | For `select`: `[{value, label}]` |
| `required` | bool | Whether the action must be completed |
| `navigateTo` | string | Page key for client-side navigation (no action emitted to agent) |

### Section Types

Sections are defined in `data.sections` (or within pages/panels). Each section has a `type` field and optional `title`, `id`, and `className`.

| Type | Purpose | Key Fields |
|------|---------|------------|
| `form` | Input fields for collecting user data | `fields`, `columns` (1 or 2), `actions` |
| `items` | List of rows with titles, subtitles, and per-item actions | `items` |
| `text` | Static text or markdown block | `content`, `format` |
| `actions` | Standalone button group | `actions` |
| `progress` | Task list with optional progress bar | `tasks`, `percentage` |
| `log` | Scrollable terminal-style log output | `lines`, `maxLines`, `autoScroll` |
| `diff` | Unified diff viewer with line numbers | `content` |
| `table` | Sortable data table with optional selection and click handling | `columns`, `rows`, `selectable`, `clickable` |
| `tabs` | Tabbed container nesting other sections | `tabs`, `activeTab` |
| `metric` | Grid of KPI/metric cards with optional sparklines | `cards`, `columns` |
| `chart` | Data-driven SVG chart (bar, line, area, pie, donut, sparkline) | `chartType`, `data` or `columns`/`rows`, `options` |

### Form Fields

Each field in a `form` section's `fields` array:

| Field | Type | Description |
|-------|------|-------------|
| `key` | string | Unique field identifier (used in form values) |
| `label` | string | Display label |
| `type` | string | `text`, `textarea`, `number`, `select`, `checkbox`, `email`, `url`, `static` |
| `value` | any | Pre-populated value |
| `default` | any | Default value if no value set |
| `placeholder` | string | Placeholder text |
| `description` | string | Helper text below the field |
| `description_format` | string | Set to `"markdown"` for markdown descriptions |
| `options` | array | For `select`: `[{value, label}]` or `["string", ...]` |
| `required` | bool | Mark field as required (validated on submit) |
| `pattern` | string | Regex validation pattern |
| `minLength` | int | Minimum input length |
| `maxLength` | int | Maximum input length |
| `errorMessage` | string | Custom validation error message |
| `className` | string | CSS class(es) to add to the field |

### Items Section

Each item in an `items` section's `items` array:

| Field | Type | Description |
|-------|------|-------------|
| `title` | string | Item title |
| `subtitle` | string | Secondary text |
| `id` | string | Item identifier (included in action context) |
| `format` | string | Set to `"markdown"` for markdown rendering of title/subtitle |
| `className` | string | CSS class(es) to add to the item row |
| `actions` | array | Per-item action buttons (same shape as `actions_requested`) |
| `navigateTo` | string | Page key for client-side navigation on click |

### Progress Section

| Field | Type | Description |
|-------|------|-------------|
| `tasks` | array | `[{label, status}]` where status is `pending`, `in_progress`, `completed`, `failed`, or `skipped` |
| `percentage` | number | 0-100 progress bar value |

### Log Section

| Field | Type | Description |
|-------|------|-------------|
| `lines` | array | Array of log line strings (supports ANSI color codes) |
| `maxLines` | int | Maximum lines to display (default: 500, older lines truncated) |
| `autoScroll` | bool | Auto-scroll to bottom on render (default: `true`) |

### Diff Section

| Field | Type | Description |
|-------|------|-------------|
| `content` | string | Unified diff text. Lines starting with `+` are additions, `-` are removals, `@@` are hunk headers |

### Table Section

| Field | Type | Description |
|-------|------|-------------|
| `columns` | array | `[{key, label}]` column definitions |
| `rows` | array | `[{key: value, ...}]` row data objects |
| `selectable` | bool | Show row checkboxes with select-all header |
| `clickable` | bool | Enable row click drill-down (emits action or navigates) |
| `clickActionId` | string | Action ID sent on row click (default: `"_table_row_click"`). Value includes full row data |
| `navigateToField` | string | Row field containing a page key for client-side navigation (no action emitted) |

Columns are sortable by default (click header to toggle ascending/descending).

### Tabs Section

| Field | Type | Description |
|-------|------|-------------|
| `tabs` | array | `[{id, label, sections: [...]}]` where each tab contains nested sections |
| `activeTab` | string | ID of the initially active tab (defaults to first tab) |

### Metric Cards Section

| Field | Type | Description |
|-------|------|-------------|
| `columns` | number | Grid column count, 1-6 (default: 4) |
| `cards` | array | Array of metric card objects (see below) |

Each card in the `cards` array:

| Field | Type | Description |
|-------|------|-------------|
| `label` | string | Card label (required) |
| `value` | string or number | Display value (required) |
| `unit` | string | Unit suffix (e.g., `"ms"`, `"%"`) |
| `change` | string | Change indicator (e.g., `"+12%"`, `"-3.5%"`) |
| `changeDirection` | string | `"up"`, `"down"`, or `"neutral"` (controls arrow and color) |
| `sparkline` | array | Array of numbers rendering an inline SVG sparkline |

### Chart Section

| Field | Type | Description |
|-------|------|-------------|
| `chartType` | string | `"bar"`, `"line"`, `"area"`, `"pie"`, `"donut"`, or `"sparkline"` |

Chart data can be provided in two formats:

**Format A -- chart-native (`data` field):**

| Field | Type | Description |
|-------|------|-------------|
| `data.labels` | array | Array of label strings (x-axis or slice labels) |
| `data.datasets` | array | `[{label, values: number[], color?}]` |

**Format B -- tabular (same shape as table sections):**

| Field | Type | Description |
|-------|------|-------------|
| `columns` | array | `[{key, label}]` -- first column becomes labels, remaining become datasets |
| `rows` | array | `[{key: value, ...}]` |

**Chart options (`options` field):**

| Field | Type | Description |
|-------|------|-------------|
| `width` | number | SVG width in pixels (default: 500, range: 50-2000) |
| `height` | number | SVG height in pixels (default: 300, range: 50-1500) |
| `showLegend` | bool | Show legend below chart (default: `true`, except sparkline) |
| `showGrid` | bool | Show grid lines |
| `stacked` | bool | Stack bars (bar chart only) |
| `barWidth` | number | Bar width factor |
| `lineWidth` | number | Line stroke width |
| `dotSize` | number | Data point dot radius |

**Colors:** Hex values (e.g., `"#ff6600"`) or theme aliases: `blue`, `green`, `red`, `yellow`, `purple`, `orange`, `cyan`, `pink`. If no color is specified per dataset, the default palette cycles through these aliases.

### SPA Pages

Multi-page navigation renders all pages into the DOM and switches between them client-side (instant, no agent round-trip).

| Field | Type | Description |
|-------|------|-------------|
| `pages` | object | Keys are page IDs (alphanumeric, dash, underscore, dot, slash). Values are page objects |
| `activePage` | string | Initial active page (defaults to first key) |
| `showNav` | bool | Show/hide the nav bar (default: `true`) |

Each page object:

| Field | Type | Description |
|-------|------|-------------|
| `label` | string | Nav tab label (required) |
| `hidden` | bool | Exclude from nav bar but still reachable via `navigateTo` (default: `false`) |
| `message` | string | Page-level message |
| `message_format` | string | Set to `"markdown"` for markdown rendering |
| `data` | object | `{sections: [...]}` -- page content |
| `actions_requested` | array | Page-level action buttons |

**Client-side navigation via `navigateTo`:**

- `actions_requested` items: add a `navigateTo` property with a page key (no action emitted)
- `items` section items: add a `navigateTo` property (click navigates instead of emitting)
- Table rows: set `navigateToField` on the table section to specify which row field contains the target page key

### Behaviors

Client-side conditional rules that show/hide fields or enable/disable actions based on form values. Evaluated on every form change and once on initial render.

| Field | Type | Description |
|-------|------|-------------|
| `behaviors` | array | Array of rule objects |

Each rule:

| Field | Type | Description |
|-------|------|-------------|
| `when` | object | `{field: "key", <condition>: <value>}` |
| `show` | array | Field keys or section IDs to show when condition is met |
| `hide` | array | Field keys or section IDs to hide when condition is met |
| `enable` | array | Action IDs to enable when condition is met |
| `disable` | array | Action IDs to disable when condition is met |

**Supported conditions:**

| Condition | Description |
|-----------|-------------|
| `equals` | Exact value match |
| `notEquals` | Value does not match |
| `in` | Value is in the given array |
| `notIn` | Value is not in the given array |
| `checked` | Boolean truthy check |
| `unchecked` | Boolean falsy check |
| `empty` | Value is `""`, `undefined`, or `null` |
| `notEmpty` | Value is not empty |
| `matches` | Regex match against string value |

### Layouts

Multi-panel layouts split the viewport into two panels.

| Field | Type | Description |
|-------|------|-------------|
| `layout` | object | `{type: "sidebar"\|"split", sidebarWidth?: "<CSS length>"}` |
| `panels` | object | Panel content (depends on layout type) |

**Sidebar layout:**

```
layout: {type: "sidebar", sidebarWidth: "300px"}
panels: {
  sidebar: {sections: [...]},
  main: {sections: [...]}
}
```

`sidebarWidth` accepts CSS lengths (`px`, `em`, `rem`, `%`). Defaults to `"300px"`.

**Split layout:**

```
layout: {type: "split"}
panels: {
  left: {sections: [...]},
  right: {sections: [...]}
}
```

### Built-in CSS Utility Classes

Available on sections, fields, and items via `className`. No `custom_css` needed.

| Class | Purpose |
|-------|---------|
| `owg-diff-add`, `owg-diff-remove`, `owg-diff-context` | Diff highlighting |
| `owg-mono`, `owg-code` | Monospace text |
| `owg-pill`, `owg-pill-green`, `owg-pill-red`, `owg-pill-blue`, `owg-pill-yellow`, `owg-pill-neutral` | Badge pills |
| `owg-callout-info`, `owg-callout-warn`, `owg-callout-error`, `owg-callout-success` | Callout boxes |
| `owg-text-green`, `owg-text-red`, `owg-text-blue`, `owg-text-yellow`, `owg-text-muted`, `owg-text-dim` | Text colors |
| `owg-compact`, `owg-no-border`, `owg-zebra` | Layout helpers for item lists |

## actions.json

Webview-to-agent responses. Written by the webview via SDK, read by the agent via `read_actions.sh`.

| Field | Type | Description |
|-------|------|-------------|
| `version` | int | Incremented on each append |
| `actions` | array | User action responses |

### Action Response Items

| Field | Type | Description |
|-------|------|-------------|
| `id` | string | UUID for this response |
| `action_id` | string | References `id` from `actions_requested` |
| `type` | string | Same types as `actions_requested` |
| `timestamp` | string | ISO 8601 when user responded |
| `value` | any | `true/false` for approve/reject, string for input, string for select, object for form data, object for table row clicks |
| `metadata` | object | Optional additional context (comments, etc.) |
| `metadata.context` | object | Per-item/section context: `{item_index, item_id, section_index, section_id, row_index}` |
