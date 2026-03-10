"""
Tests for the npm SDK package (assets/sdk/package.json + openwebgoggles-sdk.mjs).

Validates:
  - package.json structure, exports map, and version sync with pyproject.toml
  - openwebgoggles-sdk.mjs exists and contains a valid ESM re-export
  - npm-publish.yml workflow references the correct registry and paths
  - UMD detection in openwebgoggles-sdk.js (CJS + AMD + global)
"""

from __future__ import annotations

import json
import os
import re
import sys
from pathlib import Path

import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------

_REPO = Path(__file__).parents[2]  # /path/to/openwebgoggles
_SDK_DIR = _REPO / "assets" / "sdk"
_PKG_JSON = _SDK_DIR / "package.json"
_SDK_JS = _SDK_DIR / "openwebgoggles-sdk.js"
_SDK_MJS = _SDK_DIR / "openwebgoggles-sdk.mjs"
_DTS = _SDK_DIR / "openwebgoggles.d.ts"
_PYPROJECT = _REPO / "pyproject.toml"
_NPM_WF = _REPO / ".github" / "workflows" / "npm-publish.yml"


# ---------------------------------------------------------------------------
# package.json
# ---------------------------------------------------------------------------


class TestPackageJson:
    """Validate the npm package manifest."""

    @pytest.fixture(scope="class")
    def pkg(self) -> dict:
        assert _PKG_JSON.exists(), "assets/sdk/package.json must exist"
        return json.loads(_PKG_JSON.read_text())

    def test_name_is_openwebgoggles(self, pkg):
        assert pkg["name"] == "openwebgoggles"

    def test_has_version(self, pkg):
        assert "version" in pkg
        assert re.fullmatch(r"\d+\.\d+\.\d+.*", pkg["version"]), "version must be semver"

    def test_version_matches_pyproject(self, pkg):
        """npm version must match the Python package version."""
        import tomllib

        with open(_PYPROJECT, "rb") as f:
            pyproject = tomllib.load(f)
        py_version = pyproject["project"]["version"]
        assert pkg["version"] == py_version, (
            f"package.json version ({pkg['version']}) must match pyproject.toml ({py_version})"
        )

    def test_main_is_umd(self, pkg):
        assert pkg.get("main") == "./openwebgoggles-sdk.js"

    def test_module_is_esm(self, pkg):
        assert pkg.get("module") == "./openwebgoggles-sdk.mjs"

    def test_types_is_dts(self, pkg):
        assert pkg.get("types") == "./openwebgoggles.d.ts"

    def test_exports_map(self, pkg):
        exports = pkg.get("exports", {}).get(".")
        assert exports is not None, "exports['.'] must exist"
        assert exports.get("import") == "./openwebgoggles-sdk.mjs"
        assert exports.get("require") == "./openwebgoggles-sdk.js"
        assert exports.get("types") == "./openwebgoggles.d.ts"

    def test_files_includes_all_artifacts(self, pkg):
        files = set(pkg.get("files", []))
        assert "openwebgoggles-sdk.js" in files
        assert "openwebgoggles-sdk.mjs" in files
        assert "openwebgoggles.d.ts" in files

    def test_license_is_apache(self, pkg):
        assert pkg.get("license") == "Apache-2.0"

    def test_has_repository(self, pkg):
        repo = pkg.get("repository", {})
        assert repo.get("type") == "git"
        assert "openwebgoggles" in repo.get("url", "").lower()

    def test_side_effects_false(self, pkg):
        """sideEffects: false enables tree-shaking in bundlers."""
        assert pkg.get("sideEffects") is False

    def test_node_engine_at_least_16(self, pkg):
        node_req = pkg.get("engines", {}).get("node", "")
        assert node_req, "engines.node should be specified"
        # Accept >=16, >=18, etc.
        assert re.match(r">=\d+", node_req)


# ---------------------------------------------------------------------------
# ESM wrapper (openwebgoggles-sdk.mjs)
# ---------------------------------------------------------------------------


class TestEsmWrapper:
    """Validate the ESM entry point."""

    @pytest.fixture(scope="class")
    def mjs(self) -> str:
        assert _SDK_MJS.exists(), "assets/sdk/openwebgoggles-sdk.mjs must exist"
        return _SDK_MJS.read_text()

    def test_file_exists(self, mjs):
        assert len(mjs) > 0

    def test_imports_umd(self, mjs):
        """Must import from the UMD file."""
        assert "openwebgoggles-sdk.js" in mjs

    def test_has_default_export(self, mjs):
        """Must export default for `import OpenWebGoggles from 'openwebgoggles'`."""
        assert "export default" in mjs

    def test_is_esm_syntax(self, mjs):
        """Must use import/export — not require()."""
        assert "import " in mjs
        assert "require(" not in mjs

    def test_no_browser_globals(self, mjs):
        """ESM wrapper must not reference browser globals (window, document)."""
        assert "window." not in mjs
        assert "document." not in mjs


# ---------------------------------------------------------------------------
# UMD detection in openwebgoggles-sdk.js
# ---------------------------------------------------------------------------


class TestUmdDetection:
    """The UMD wrapper must detect all three environments."""

    @pytest.fixture(scope="class")
    def src(self) -> str:
        assert _SDK_JS.exists(), "assets/sdk/openwebgoggles-sdk.js must exist"
        return _SDK_JS.read_text()

    def test_amd_detection(self, src):
        """Must detect AMD (RequireJS) environment."""
        assert "define" in src and "define.amd" in src

    def test_cjs_detection(self, src):
        """Must detect CommonJS (Node.js) environment."""
        assert "module.exports" in src

    def test_global_fallback(self, src):
        """Must fall back to global (browser window/self)."""
        assert "root" in src or "self" in src

    def test_returns_constructor(self, src):
        """Factory must return the OpenWebGoggles constructor."""
        assert "return OpenWebGoggles" in src


# ---------------------------------------------------------------------------
# npm publish workflow
# ---------------------------------------------------------------------------


class TestNpmPublishWorkflow:
    """Validate the npm-publish.yml GitHub Actions workflow."""

    @pytest.fixture(scope="class")
    def wf(self) -> str:
        assert _NPM_WF.exists(), ".github/workflows/npm-publish.yml must exist"
        return _NPM_WF.read_text()

    def test_triggers_on_release_published(self, wf):
        assert "release" in wf
        assert "published" in wf

    def test_uses_npmjs_registry(self, wf):
        assert "registry.npmjs.org" in wf

    def test_version_check_present(self, wf):
        """Workflow must verify package.json version matches the git tag."""
        assert "package.json" in wf
        assert "version" in wf.lower()

    def test_publishes_from_sdk_dir(self, wf):
        """npm publish must run from assets/sdk/."""
        assert "assets/sdk" in wf

    def test_requires_npm_token_secret(self, wf):
        assert "NPM_TOKEN" in wf

    def test_uses_pinned_actions(self, wf):
        """All uses: lines must pin to a full SHA, not a mutable tag."""
        uses_lines = [line.strip() for line in wf.splitlines() if line.strip().startswith("uses:")]
        for line in uses_lines:
            # SHA is 40 hex chars after the @
            assert re.search(r"@[0-9a-f]{40}", line), f"Action not pinned to SHA: {line}"
