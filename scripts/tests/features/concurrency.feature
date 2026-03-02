Feature: Concurrent access handling
  As a server operator
  I want the system to handle concurrent operations safely
  So that race conditions don't corrupt state

  Scenario: Concurrent webview_close during active tool call
    Given a webview session is active
    And a tool call is in progress
    When webview_close is called concurrently
    Then the tool call should complete or fail gracefully
    And the session should be properly cleaned up

  Scenario: Multiple rapid state updates
    Given a webview session is active
    When three webview_update calls are made in rapid succession
    Then all updates should be applied
    And the final state should reflect the last update

  Scenario: webview_status during session teardown
    Given a webview session is active
    When webview_close and webview_status race
    Then webview_status should return no active session or active session
    And no exception should propagate

  Scenario: Lock acquisition under contention
    Given a webview session is active
    When two tool calls try to acquire the session lock simultaneously
    Then both should eventually succeed
    And state should remain consistent

  Scenario: Crypto fallback when NaCl unavailable
    Given PyNaCl is not installed
    When HMAC signing is attempted
    Then it should succeed with symmetric key only
    And Ed25519 operations should gracefully degrade
