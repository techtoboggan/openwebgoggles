Feature: Stale server communicates clearly to MCP host
  After detecting a package upgrade, the server must communicate
  this to the MCP host both proactively and reactively.

  Scenario: Tool call rejected when server is stale
    Given the server has been marked as stale
    When a tool call is made
    Then the response should contain an error message
    And the error should mention restart

  Scenario: Stale flag persists across multiple tool calls
    Given the server has been marked as stale
    When multiple tool calls are made
    Then all should return the stale error
    And none should execute the tool function

  Scenario: Active tool call count decrements on exception
    Given a tool call is in progress
    When the tool function raises an exception
    Then the active tool call count should decrement to zero

  Scenario: Proactive host notification sent on staleness
    Given the MCP server session is active
    When the server is marked as stale
    Then a log notification should be attempted to the host

  Scenario: Proactive notification fails gracefully
    Given the MCP server session is not available
    When the server is marked as stale
    Then the notification attempt should not raise
    And the stale flag should still be set
