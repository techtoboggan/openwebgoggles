Feature: Anti-zombification guardrails
  Coding agents have a tendency to "forget" they have an open browser
  session and stop sending updates. The system must give agents enough
  guidance at every step to stay on-rails and keep the user informed.

  Scenario: openwebgoggles tool returns a _hint reminding agent to continue
    Given the agent calls openwebgoggles with a simple state
    When the tool returns
    Then the result should contain a "_hint" key
    And the hint text should be non-empty
    And the hint should mention the session is still open

  Scenario: openwebgoggles_ping updates the display in app mode
    Given the host has fetched the UI resource
    When the agent calls openwebgoggles_ping with message "Analyzing files"
    Then the app state should be updated with status "processing"
    And the state should include the message text
    And the result should contain a "_hint" key

  Scenario: openwebgoggles_ping works in browser mode
    Given the host has not fetched the UI resource
    And a browser session is open
    When the agent calls openwebgoggles_ping with message "Running tests"
    Then the session state should be updated with a processing indicator
    And the result should contain a "_hint" key

  Scenario: openwebgoggles_status includes hint about open sessions
    Given a named session "work" is open
    When the agent calls openwebgoggles_status
    Then the result should contain a "_hint" key
    And the hint should mention closing the session when done

  Scenario: Workflow prompt is registered and contains key guidance
    When the agent host fetches the openwebgoggles_workflow prompt
    Then the prompt text should be non-empty
    And the prompt should mention openwebgoggles_read
    And the prompt should mention openwebgoggles_close
    And the prompt should mention the attention action type

  Scenario: openwebgoggles_ping is rejected by SecurityGate if message is too long
    When the agent calls openwebgoggles_ping with a 1000-character message
    Then the call should succeed with a truncated or validated message
