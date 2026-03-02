Feature: CLI commands interact correctly with server states
  The restart, status, and doctor commands must handle all
  combinations of running, stopped, and stale server states.

  Scenario: SIGUSR1 restart triggers reload flag
    Given the MCP server is running
    When SIGUSR1 is received
    Then the signal handler should set the reload flag
    And the signal monitor should detect the flag

  Scenario: Status reports running server
    Given the MCP server PID file exists with a live PID
    When openwebgoggles status is run
    Then it should report the server as running

  Scenario: Status reports no running server
    Given no PID files exist
    When openwebgoggles status is run
    Then it should report no server running

  Scenario: Doctor detects stale PID files
    Given a PID file exists with a dead process ID
    When openwebgoggles doctor is run
    Then it should report the stale PID
