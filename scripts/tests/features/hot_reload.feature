Feature: Hot-reload detects package upgrades
  The MCP server's version monitor should detect when the openwebgoggles
  package has been upgraded via pipx/pip and mark the server as stale,
  rejecting subsequent tool calls with a clear restart message.

  Background:
    Given the MCP server is running with version "1.0.0"
    And the version monitor is active

  Scenario: Version change detected via mtime change
    When the dist-info directory mtime changes
    And the installed version becomes "2.0.0"
    Then the server should be marked as stale
    And the stale message should mention "1.0.0" and "2.0.0"

  Scenario: Same version after mtime change is a no-op
    When the dist-info directory mtime changes
    And the installed version is still "1.0.0"
    Then the server should NOT be marked as stale

  Scenario: Package temporarily missing during upgrade
    When the dist-info directory is temporarily deleted
    And the version returns unknown
    Then the server should NOT be marked as stale
    And the monitor should continue polling

  Scenario: Package reappears after deletion with new version
    Given the dist-info directory was temporarily deleted
    When the dist-info reappears with version "2.0.0"
    Then the server should be marked as stale
    And the stale message should mention "1.0.0" and "2.0.0"

  Scenario: dist-info path is recovered after unknown transition
    Given the dist-info path was lost during upgrade
    When the package is reinstalled with version "2.0.0"
    Then the dist-info path should be re-discovered
    And the server should be marked as stale

  Scenario: Monitor survives transient errors
    When the monitor encounters 3 consecutive errors
    Then the monitor should still be running
    And errors should be logged with backoff

  Scenario: Monitor gives up after too many consecutive errors
    When the monitor encounters 10 consecutive errors
    Then the monitor should stop
    And a fatal error should be logged

  Scenario: Background task crash is logged via done-callback
    When the version monitor task raises an unhandled exception
    Then the exception should be logged via done-callback

  Scenario: Webview session is closed when server becomes stale
    Given the webview session is active
    When a version change is detected to "2.0.0"
    Then the webview session should be closed gracefully
    And the session reference should be cleared
