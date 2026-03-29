Feature: Agent liveness detection
  The browser panel must accurately reflect whether the coding agent
  is actively waiting for user input so the user knows whether
  further interaction is worthwhile.

  Background:
    Given the server has a valid data directory

  Scenario: Status is "waiting" when agent is actively polling
    Given the agent liveness file exists and is fresh
    When the browser polls the agent-status endpoint
    Then the response should report waiting as true
    And the response should report was_active as true
    And the response should include an age under 10 seconds

  Scenario: Status shows stale agent when liveness file is old
    Given the agent liveness file exists but is 30 seconds old
    When the browser polls the agent-status endpoint
    Then the response should report waiting as false
    And the response should report was_active as true
    And the response should not include an age field

  Scenario: Status shows never-connected when no liveness file
    Given no agent liveness file exists
    When the browser polls the agent-status endpoint
    Then the response should report waiting as false
    And the response should report was_active as false

  Scenario: Agent-status endpoint requires authentication
    Given no agent liveness file exists
    When an unauthenticated client polls the agent-status endpoint
    Then the response should be 401 Unauthorized

  Scenario: Liveness file is created when agent starts waiting
    Given the agent has no pending actions
    When wait_for_action begins
    Then the liveness file should exist within 1 second
    And the liveness file should contain a float timestamp

  Scenario: Liveness file is removed when action is received
    Given the agent is waiting for an action
    When a user action arrives
    Then the liveness file should be removed after wait_for_action returns

  Scenario: Liveness file is removed when wait is cancelled
    Given the agent is waiting for an action
    When the wait_for_action task is cancelled
    Then the liveness file should be removed
