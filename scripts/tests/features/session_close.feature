Feature: Session close and user-initiated exit
  The user must be able to close a browser session cleanly and the
  coding agent must be notified immediately so it does not continue
  sending updates to a dead window.

  Scenario: session_closed action breaks the agent out of wait_for_action
    Given the agent is waiting for a user action
    When the user sends a session_closed action
    Then wait_for_action should return with action_type "session_closed"
    And the agent should not remain blocked

  Scenario: attention action re-engages the agent from wait_for_action
    Given the agent is waiting for a user action
    When the user clicks "Remind Agent" sending an attention action
    Then wait_for_action should return with action_type "attention"
    And the result should include a reason field

  Scenario: SecurityGate accepts session_closed action type
    Given a well-formed action payload with type "session_closed"
    When the SecurityGate validates the action
    Then the action should be accepted

  Scenario: SecurityGate accepts attention action type
    Given a well-formed action payload with type "attention"
    When the SecurityGate validates the action
    Then the action should be accepted

  Scenario: SecurityGate rejects unknown action types
    Given a well-formed action payload with type "malicious_action"
    When the SecurityGate validates the action
    Then the action should be rejected

  Scenario: Internal page-switch events are not surfaced to the agent
    Given the agent is waiting for a user action
    When the browser sends a _page_switch internal event
    Then wait_for_action should continue polling and not return
