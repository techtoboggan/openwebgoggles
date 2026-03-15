/**
 * OpenWebGoggles TypeScript Definitions
 *
 * Type definitions for the OpenWebGoggles browser SDK.
 * Covers the full state schema, all public methods, and event types.
 */

// ---------------------------------------------------------------------------
// Field types
// ---------------------------------------------------------------------------

export type OWGFieldType =
  | "text"
  | "textarea"
  | "number"
  | "select"
  | "checkbox"
  | "email"
  | "url"
  | "static"
  | "slider"
  | "date"
  | "datetime"
  | "autocomplete"
  | "file";

export interface OWGField {
  key: string;
  label: string;
  type: OWGFieldType;
  value?: unknown;
  default?: unknown;
  placeholder?: string;
  description?: string;
  description_format?: "markdown";
  options?: string[];
  required?: boolean;
  pattern?: string;
  minLength?: number;
  maxLength?: number;
  errorMessage?: string;
  format?: "markdown";
  className?: string;
  /** slider: minimum value */
  min?: number;
  /** slider: maximum value */
  max?: number;
  /** slider: step increment */
  step?: number;
  /** slider: unit label shown next to current value */
  unit?: string;
  /** autocomplete: if false, submitted value must be one of options */
  allowCustom?: boolean;
  /** file: accepted MIME types or extensions, e.g. "image/*,.pdf" */
  accept?: string;
  /** file: allow selecting multiple files */
  multiple?: boolean;
  /** file: maximum file size in bytes (default: 524288 = 512 KB) */
  maxSize?: number;
}

// ---------------------------------------------------------------------------
// Actions
// ---------------------------------------------------------------------------

export type OWGActionType =
  | "approve"
  | "reject"
  | "submit"
  | "primary"
  | "danger"
  | "success"
  | "warning"
  | "ghost";

export interface OWGAction {
  id: string;
  label: string;
  type: OWGActionType;
  /** Client-side navigation — switches page without an agent round-trip */
  navigateTo?: string;
}

// ---------------------------------------------------------------------------
// Section types
// ---------------------------------------------------------------------------

export type OWGSectionType =
  | "form"
  | "items"
  | "text"
  | "actions"
  | "progress"
  | "log"
  | "diff"
  | "table"
  | "tabs"
  | "metric"
  | "chart"
  | "tree"
  | "timeline"
  | "heatmap"
  | "network";

export type OWGProgressTaskStatus =
  | "pending"
  | "in_progress"
  | "completed"
  | "failed"
  | "skipped";

export interface OWGProgressTask {
  label: string;
  status: OWGProgressTaskStatus;
}

export interface OWGColumn {
  key: string;
  label: string;
}

export interface OWGItem {
  title: string;
  subtitle?: string;
  id?: string;
  format?: "markdown";
  className?: string;
  actions?: OWGAction[];
  navigateTo?: string;
}

export interface OWGMetricCard {
  label: string;
  value: string | number;
  delta?: string;
  trend?: "up" | "down" | "neutral";
  unit?: string;
  sparkline?: number[];
}

export type OWGChartType = "bar" | "line" | "area" | "pie" | "donut" | "sparkline";

export interface OWGTab {
  id: string;
  label: string;
  sections: OWGSection[];
}

export interface OWGTimelineItem {
  /** Display label (required) */
  label: string;
  /** Start date in YYYY-MM-DD format (required) */
  start: string;
  /** End date in YYYY-MM-DD format (required) */
  end: string;
  /** Bar color: named theme color or hex (#rrggbb) */
  color?: string;
  /** Optional group label for visual grouping */
  group?: string;
}

export interface OWGNetworkNode {
  /** Node identifier (required) */
  id: string;
  /** Display label (defaults to id if omitted) */
  label?: string;
  /** Node fill color: named theme color or hex (#rrggbb) */
  color?: string;
}

export interface OWGTreeNode {
  /** Display label (required) */
  label: string;
  /** Optional identifier passed back in action payload when clicked */
  id?: string;
  /** Short badge shown alongside the label (e.g. "modified", "added") */
  badge?: string;
  /** Nested child nodes */
  children?: OWGTreeNode[];
}

export interface OWGSection {
  type: OWGSectionType;
  title?: string;
  id?: string;
  className?: string;
  format?: "markdown";
  /** Wrap section in a collapsible container */
  collapsible?: boolean;
  /** Start the section collapsed */
  collapsed?: boolean;

  // form
  fields?: OWGField[];

  // items (type: "items") / timeline (type: "timeline") — same key, different element shape
  items?: OWGItem[] | OWGTimelineItem[];

  // text / diff
  content?: string;
  /** Show a copy-to-clipboard button */
  copyable?: boolean;

  // progress
  tasks?: OWGProgressTask[];
  percentage?: number;

  // log
  lines?: string[];
  autoScroll?: boolean;
  maxLines?: number;

  // table
  columns?: OWGColumn[];
  rows?: Record<string, unknown>[];
  clickable?: boolean;
  clickActionId?: string;
  navigateToField?: string;
  /** Show live search/filter bar above table */
  filterable?: boolean;
  filterPlaceholder?: string;
  selectable?: boolean;

  // tabs
  tabs?: OWGTab[];

  // metric
  cards?: OWGMetricCard[];

  // chart
  chartType?: OWGChartType;
  data?: {
    labels?: string[];
    datasets?: Array<{ label?: string; data: number[]; color?: string }>;
  };

  // network
  edges?: Array<{ from: string; to: string; label?: string }>;

  // heatmap
  xLabels?: string[];
  yLabels?: string[];
  values?: number[][];
  /** Color scale: [minColor, maxColor], hex or named theme color */
  colorScale?: [string, string];

  // tree (type: "tree") / network (type: "network") — same key, different element shape
  nodes?: OWGTreeNode[] | OWGNetworkNode[];
  /** Expand all tree nodes on initial render (default: false — all collapsed) */
  expandAll?: boolean;
  /** Clicking a node fires an action (id sent as nodeId in payload) */
  clickActionId?: string;

}

// ---------------------------------------------------------------------------
// Pages and behaviors
// ---------------------------------------------------------------------------

export interface OWGPage {
  label?: string;
  /** Exclude from the navigation bar (page is still reachable via navigateTo) */
  hidden?: boolean;
  data: { sections: OWGSection[] };
  actions_requested?: OWGAction[];
}

export interface OWGBehaviorCondition {
  field: string;
  equals?: unknown;
  in?: unknown[];
  checked?: boolean;
}

export interface OWGBehavior {
  when: OWGBehaviorCondition;
  show?: string[];
  hide?: string[];
  enable?: string[];
  disable?: string[];
}

// ---------------------------------------------------------------------------
// Top-level state
// ---------------------------------------------------------------------------

export interface OWGState {
  title?: string;
  message?: string;
  message_format?: "markdown";
  message_className?: string;
  status?: string;
  version?: number;
  custom_css?: string;
  data?: { sections: OWGSection[] };
  pages?: Record<string, OWGPage>;
  activePage?: string;
  showNav?: boolean;
  actions_requested?: OWGAction[];
  behaviors?: OWGBehavior[];
  layout?: { type: "sidebar" | "split"; sidebarWidth?: string };
  panels?: {
    sidebar?: { sections: OWGSection[] };
    main?: { sections: OWGSection[] };
  };
}

// ---------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------

export interface OWGManifest {
  session: { token: string };
  server?: {
    host?: string;
    ws_port?: number;
    http_port?: number;
  };
}

// ---------------------------------------------------------------------------
// SDK events
// ---------------------------------------------------------------------------

export type OWGEventName =
  | "connected"
  | "disconnected"
  | "state_updated"
  | "state_patched"
  | "manifest_updated"
  | "actions_updated"
  | "actions_cleared"
  | "close"
  | "error";

export type OWGPatchOpType = "set" | "append" | "merge";

export interface OWGPatchOp {
  op: OWGPatchOpType;
  /** Dot-separated path to the target field (e.g. "data.sections.0.lines") */
  path: string;
  value: unknown;
}

export type OWGUnsubscribeFn = () => void;

// ---------------------------------------------------------------------------
// Constructor options
// ---------------------------------------------------------------------------

export interface OWGOptions {
  /** Base HTTP URL for the webview server (default: window.location.origin) */
  httpUrl?: string;
  /** WebSocket URL override (default: derived from manifest) */
  wsUrl?: string;
  /** HTTP polling interval in milliseconds when WebSocket is unavailable (default: 2000) */
  pollInterval?: number;
}

// ---------------------------------------------------------------------------
// SDK class
// ---------------------------------------------------------------------------

declare class OpenWebGoggles {
  /**
   * Create a new OpenWebGoggles SDK instance.
   * @param options - Optional configuration overrides.
   */
  constructor(options?: OWGOptions);

  // --- Event system ---

  /**
   * Register a listener for an SDK event.
   * Returns an unsubscribe function — call it to remove the listener.
   * Duplicate registrations of the same callback are silently ignored.
   * Max 100 listeners per event (oldest removed when exceeded).
   */
  on(event: OWGEventName | string, callback: (data: unknown) => void): OWGUnsubscribeFn;

  /**
   * Shorthand: listen for state updates.
   * Equivalent to `on("state_updated", callback)`.
   */
  onStateUpdate(callback: (state: OWGState) => void): OWGUnsubscribeFn;

  /**
   * Shorthand: listen for manifest updates.
   * Equivalent to `on("manifest_updated", callback)`.
   */
  onManifestUpdate(callback: (manifest: OWGManifest) => void): OWGUnsubscribeFn;

  // --- Connection ---

  /**
   * Connect to the webview server.
   * Fetches the manifest, bootstraps auth, opens a WebSocket (with HTTP polling fallback).
   * Resolves with `this` once the initial state is available.
   */
  connect(): Promise<OpenWebGoggles>;

  /**
   * Disconnect from the server.
   * Closes the WebSocket, stops polling, and cancels reconnect timers.
   * Emits the `"disconnected"` event.
   */
  disconnect(): void;

  /**
   * Returns true if the SDK has a live connection to the server.
   */
  isConnected(): boolean;

  // --- State accessors ---

  /** Returns the current full state object, or null before connect. */
  getState(): OWGState | null;

  /** Returns `state.status`, or null before connect. */
  getStatus(): string | null;

  /** Returns `state.data`, or null before connect. */
  getData(): OWGState["data"] | null;

  /** Returns `state.actions_requested` array, or empty array before connect. */
  getRequestedActions(): OWGAction[];

  /** Returns the server manifest, or null before connect. */
  getManifest(): OWGManifest | null;

  // --- Actions (Webview → Agent) ---

  /**
   * Send an action to the agent.
   * Automatically routes through WebSocket (signed) or HTTP fallback.
   * Actions submitted while WebSocket is connecting are queued and flushed after auth.
   */
  sendAction(
    actionId: string,
    type: string,
    value: unknown,
    metadata?: Record<string, unknown>,
  ): Promise<unknown>;

  /** Send an approve action (type="approve", value=true). */
  approve(actionId: string, metadata?: Record<string, unknown>): Promise<unknown>;

  /** Send a reject action (type="reject", value=false). */
  reject(actionId: string, metadata?: Record<string, unknown>): Promise<unknown>;

  /** Send a text input action (type="input"). */
  submitInput(actionId: string, value: unknown, metadata?: Record<string, unknown>): Promise<unknown>;

  /** Send a select action (type="select"). */
  selectOption(actionId: string, value: unknown, metadata?: Record<string, unknown>): Promise<unknown>;

  /** Send a confirm action (type="confirm", value=true). */
  confirm(actionId: string, metadata?: Record<string, unknown>): Promise<unknown>;

  // --- Static helpers ---

  /**
   * Format an ISO 8601 timestamp string into a locale-aware display string.
   * Returns an empty string if the input is falsy or unparseable.
   */
  static formatTimestamp(isoString: string): string;
}

export = OpenWebGoggles;
export as namespace OpenWebGoggles;
