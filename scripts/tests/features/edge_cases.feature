Feature: Edge case handling
  As a server operator
  I want the system to handle unexpected inputs gracefully
  So that errors don't cascade into security issues

  Scenario: Internal actions filtered from wait_for_action
    Given a webview session is active
    When an action with id "_page_switch" is submitted
    And wait_for_action is called
    Then the internal action should be filtered out
    And wait_for_action should continue polling

  Scenario: Corrupted state.json on disk
    Given a webview session has written state
    When the state.json file is corrupted with invalid JSON
    Then reading state should return a safe default
    And no exception should propagate

  Scenario: SecurityGate rejection during merge_state
    Given a webview session with a security gate
    When webview_update is called with merge containing dangerous CSS
    Then the update should be rejected
    And the original state should be preserved

  Scenario: Unknown preset in webview_update
    Given a webview session is active
    When webview is called with preset "nonexistent"
    Then it should raise a ValueError
    And the error should name the invalid preset

  Scenario: webview_close XSS in message parameter
    Given a webview session is active
    When webview_close is called with a script tag in the message
    Then the script should be escaped or rejected
    And no raw HTML should reach the client
