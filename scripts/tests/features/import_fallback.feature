Feature: Import fallback resolves modules in all install contexts
  Both relative (package) and absolute (source) imports must work
  for crypto_utils, security_gate, and other internal modules.

  Scenario: Relative import succeeds in package context
    Given the module is imported as a package
    When mcp_server imports security_gate
    Then the relative import should succeed

  Scenario: Absolute import fallback in source context
    Given the module is run from the source directory
    When mcp_server imports security_gate
    Then the absolute import should succeed as fallback

  Scenario: webview_server crypto_utils relative import
    Given webview_server is imported as a package
    When it imports crypto_utils
    Then the relative import should succeed
    And HAS_CRYPTO should be True

  Scenario: webview_server crypto_utils absolute fallback
    Given webview_server is run from source
    When it imports crypto_utils
    Then the absolute import should succeed as fallback
    And HAS_CRYPTO should be True

  Scenario: Both imports fail gracefully
    Given neither relative nor absolute import can resolve
    When the import is attempted
    Then the module should still load
    And the feature flag should be False
