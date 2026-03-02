Feature: MCP server lifespan lifecycle
  The MCP server must handle the full lifecycle: initialize background
  tasks, yield quickly to avoid timeouts, and clean up on shutdown.

  Scenario: Lifespan starts background monitor tasks
    When the MCP server lifespan starts
    Then the version monitor task should be created
    And the signal monitor task should be created
    And both tasks should have done-callbacks attached

  Scenario: Lifespan yields quickly without blocking
    When the MCP server lifespan starts
    Then the lifespan should yield within 1 second
    And the version metadata lookup should run asynchronously

  Scenario: PID file is written on startup and removed on shutdown
    When the MCP server lifespan starts
    Then the PID file should exist
    When the server shuts down
    Then the PID file should be removed

  Scenario: Lifespan cleans up on shutdown
    Given the MCP server lifespan is active
    When the server shuts down
    Then the version monitor task should be cancelled
    And the signal monitor task should be cancelled
    And the webview session should be closed

  Scenario: Lifespan handles session close failure gracefully
    Given the webview session close raises an exception
    When the server shuts down
    Then the exception should be suppressed
    And the session reference should be cleared
