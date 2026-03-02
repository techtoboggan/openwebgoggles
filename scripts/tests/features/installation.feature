Feature: Package version detection across install contexts
  The version detection system must work correctly across pip install,
  pipx install, editable install, and source-only contexts.

  Scenario: Detect version from installed package metadata
    Given openwebgoggles is installed via pip
    When get_installed_version_info is called
    Then it should return the installed version string
    And it should return the dist-info path

  Scenario: Return unknown when package is not installed
    Given openwebgoggles is not installed
    When get_installed_version_info is called
    Then it should return unknown
    And the path should be None

  Scenario: Fresh version read bypasses importlib cache
    Given a dist-info directory exists with METADATA version "2.0.0"
    When read_version_fresh is called with the dist-info hint
    Then it should return "2.0.0"
    And it should read directly from disk

  Scenario: Fresh version read scans site-packages as fallback
    Given the dist-info hint path no longer exists
    And a dist-info directory exists in site-packages
    When read_version_fresh is called without a hint
    Then it should find the version via site-packages scan
