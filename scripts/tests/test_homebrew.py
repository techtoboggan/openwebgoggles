"""
Tests for the Homebrew formula and update workflow (Phase 5.1).

Validates Formula/openwebgoggles.rb structure and .github/workflows/homebrew-update.yml
without actually running Homebrew (so tests pass on all platforms).
"""

from __future__ import annotations

import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO = Path(__file__).parents[2]
_FORMULA = _REPO / "Formula" / "openwebgoggles.rb"
_WORKFLOW = _REPO / ".github" / "workflows" / "homebrew-update.yml"
_PYPROJECT = _REPO / "pyproject.toml"


# ---------------------------------------------------------------------------
# Formula
# ---------------------------------------------------------------------------


class TestHomebrewFormula:
    """Validate the Homebrew formula file."""

    @pytest.fixture(scope="class")
    def formula(self) -> str:
        assert _FORMULA.exists(), "Formula/openwebgoggles.rb must exist"
        return _FORMULA.read_text()

    def test_class_name(self, formula):
        """Class name must be Openwebgoggles (CamelCase per Homebrew convention)."""
        assert "class Openwebgoggles < Formula" in formula

    def test_desc_present(self, formula):
        assert "desc " in formula

    def test_homepage_github(self, formula):
        assert "homepage" in formula
        assert "openwebgoggles" in formula.lower()

    def test_url_points_to_pypi_sdist(self, formula):
        assert "pythonhosted.org" in formula
        assert "openwebgoggles-" in formula
        assert ".tar.gz" in formula

    def test_license_apache(self, formula):
        assert 'license "Apache-2.0"' in formula

    def test_depends_python(self, formula):
        """Must declare a Python dependency."""
        assert "python" in formula.lower() and "depends_on" in formula

    def test_has_websockets_resource(self, formula):
        """Must include websockets as a resource."""
        assert 'resource "websockets"' in formula

    def test_has_pynacl_resource(self, formula):
        assert 'resource "PyNaCl"' in formula

    def test_has_mcp_resource(self, formula):
        assert 'resource "mcp"' in formula

    def test_uses_virtualenv(self, formula):
        """Must use Homebrew's Python::Virtualenv mixin."""
        assert "Language::Python::Virtualenv" in formula
        assert "virtualenv_install_with_resources" in formula

    def test_has_test_block(self, formula):
        """Must include a `test do` block to verify installation."""
        assert "test do" in formula

    def test_test_block_calls_binary(self, formula):
        """Test block must invoke the installed binary via #{bin}/..."""
        assert "openwebgoggles" in formula
        assert "#{bin}" in formula  # Ruby string interpolation for the Homebrew bin dir

    def test_head_url(self, formula):
        """Should include a head URL for installing from main."""
        assert "head " in formula

    def test_version_in_url(self, formula):
        """URL should contain a version number."""
        assert re.search(r"openwebgoggles-\d+\.\d+\.\d+\.tar\.gz", formula)

    def test_version_matches_pyproject(self, formula):
        """Formula URL version must match pyproject.toml."""
        import tomllib

        with open(_PYPROJECT, "rb") as f:
            pyproject = tomllib.load(f)
        py_version = pyproject["project"]["version"]
        assert py_version in formula, f"Formula must reference pyproject.toml version {py_version}"


# ---------------------------------------------------------------------------
# Homebrew update workflow
# ---------------------------------------------------------------------------


class TestHomebrewUpdateWorkflow:
    """Validate the homebrew-update.yml GitHub Actions workflow."""

    @pytest.fixture(scope="class")
    def wf(self) -> str:
        assert _WORKFLOW.exists(), ".github/workflows/homebrew-update.yml must exist"
        return _WORKFLOW.read_text()

    def test_triggers_on_release_published(self, wf):
        assert "release" in wf
        assert "published" in wf

    def test_targets_homebrew_tap_repo(self, wf):
        assert "homebrew-tap" in wf

    def test_computes_sha256(self, wf):
        assert "sha256" in wf.lower() or "SHA256" in wf

    def test_requires_tap_token_secret(self, wf):
        assert "HOMEBREW_TAP_TOKEN" in wf

    def test_opens_pull_request(self, wf):
        """Must open a PR against the tap (not force-push directly)."""
        assert "pull-request" in wf.lower() or "create-pull-request" in wf

    def test_retries_pypi_download(self, wf):
        """PyPI publish is not instant — workflow must retry the download."""
        assert "retry" in wf.lower() or "seq" in wf or "sleep" in wf

    def test_uses_pinned_actions(self, wf):
        """All uses: lines must pin to a full commit SHA."""
        uses_lines = [l.strip() for l in wf.splitlines() if l.strip().startswith("uses:")]
        for line in uses_lines:
            assert re.search(r"@[0-9a-f]{40}", line), f"Action not pinned to SHA: {line}"

    def test_copies_formula_from_repo(self, wf):
        """Workflow must use the formula file committed in this repo as the source."""
        assert "Formula/openwebgoggles.rb" in wf
