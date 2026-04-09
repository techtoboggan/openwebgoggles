Feature: MCP Apps dual-mode support
  OpenWebGoggles supports rendering UIs natively in MCP Apps hosts
  (Claude Desktop, VS Code) via structuredContent, while falling back
  to a browser window for CLI-based hosts.

  Scenario: App mode returns structuredContent without launching browser
    Given the host has fetched the UI resource
    When the agent calls webview with title "Test UI"
    Then the result should contain structuredContent
    And no browser subprocess should be launched

  Scenario: Browser fallback when host lacks MCP Apps
    Given the host has not fetched the UI resource
    When the agent calls webview with title "Fallback UI"
    Then the browser fallback should be used

  Scenario: Browser mode is non-blocking — agent polls openwebgoggles_read
    Given the host has not fetched the UI resource
    When the agent calls webview with title "Fallback UI"
    Then openwebgoggles returns ui_ready immediately
    And openwebgoggles_read returns empty actions before user acts
    And openwebgoggles_read returns actions after user submits

  Scenario: User action received via _owg_action
    Given the host has fetched the UI resource
    And the agent has displayed a webview
    When the user clicks a button with action_id "approve"
    Then webview_read should return the action
    And the action should have action_id "approve"

  Scenario: App mode state is cleared on webview_close
    Given the host has fetched the UI resource
    And the agent has displayed a webview
    When the agent calls webview_close
    Then the app mode state should be empty
