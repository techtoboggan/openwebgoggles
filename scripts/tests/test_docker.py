"""
Tests for the Docker image setup (Dockerfile, .dockerignore, docker-publish.yml).

Validates structure, security properties, and workflow configuration
without actually running Docker (so tests pass in all environments).
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
_DOCKERFILE = _REPO / "Dockerfile"
_DOCKERIGNORE = _REPO / ".dockerignore"
_ENTRYPOINT = _REPO / "docker-entrypoint.sh"
_WORKFLOW = _REPO / ".github" / "workflows" / "docker-publish.yml"


# ---------------------------------------------------------------------------
# Dockerfile
# ---------------------------------------------------------------------------


class TestDockerfile:
    """Validate Dockerfile structure and security properties."""

    @pytest.fixture(scope="class")
    def df(self) -> str:
        assert _DOCKERFILE.exists(), "Dockerfile must exist"
        return _DOCKERFILE.read_text()

    def test_uses_slim_base(self, df):
        """Base image must use slim variant to minimise attack surface."""
        assert "slim" in df, "Dockerfile must use a slim base image"

    def test_multi_stage_build(self, df):
        """Must use multi-stage build (builder + runtime)."""
        from_lines = [l.strip() for l in df.splitlines() if l.strip().upper().startswith("FROM ")]
        assert len(from_lines) >= 2, "Must have at least two FROM stages"
        # Confirm the stages have distinct aliases
        aliases = [l.split()[-1] for l in from_lines if " AS " in l.upper()]
        assert len(aliases) >= 2, "Both stages must have aliases"

    def test_non_root_user(self, df):
        """Container must run as a non-root user (CIS 4.1)."""
        assert "USER" in df, "Dockerfile must set a USER"
        # The user line must not be 'root'
        user_lines = [l.strip() for l in df.splitlines() if l.strip().startswith("USER")]
        for line in user_lines:
            assert "root" not in line.lower(), f"Must not run as root: {line}"

    def test_exposes_correct_ports(self, df):
        """Must expose ports 18420 (HTTP) and 18421 (WebSocket)."""
        assert "18420" in df, "Must EXPOSE HTTP port 18420"
        assert "18421" in df, "Must EXPOSE WebSocket port 18421"

    def test_has_healthcheck(self, df):
        """Must have a HEALTHCHECK directive."""
        assert "HEALTHCHECK" in df

    def test_has_oci_labels(self, df):
        """Must include OCI image labels."""
        assert "org.opencontainers.image" in df

    def test_has_entrypoint(self, df):
        """Must define an ENTRYPOINT."""
        assert "ENTRYPOINT" in df

    def test_python_version_arg(self, df):
        """Python version must be parameterised with ARG."""
        assert "PYTHON_VERSION" in df

    def test_venv_isolation(self, df):
        """Dependencies must be installed into an isolated venv."""
        assert "venv" in df.lower()

    def test_chown_runtime_files(self, df):
        """Runtime files must be owned by the non-root user."""
        # Either chown in RUN or --chown in COPY
        assert "chown" in df.lower() or "owg" in df


# ---------------------------------------------------------------------------
# .dockerignore
# ---------------------------------------------------------------------------


class TestDockerignore:
    """Validate the .dockerignore exclusion list."""

    @pytest.fixture(scope="class")
    def di(self) -> str:
        assert _DOCKERIGNORE.exists(), ".dockerignore must exist"
        return _DOCKERIGNORE.read_text()

    def test_excludes_git(self, di):
        assert ".git" in di

    def test_excludes_pycache(self, di):
        assert "__pycache__" in di or "*.pyc" in di

    def test_excludes_venv(self, di):
        assert ".venv" in di or "venv/" in di

    def test_excludes_pytest_cache(self, di):
        assert ".pytest_cache" in di

    def test_excludes_dist(self, di):
        assert "dist/" in di

    def test_excludes_data_dirs(self, di):
        """User data directories must not be baked into the image."""
        assert ".openwebgoggles" in di


# ---------------------------------------------------------------------------
# Entrypoint script
# ---------------------------------------------------------------------------


class TestEntrypoint:
    """Validate the docker-entrypoint.sh script."""

    @pytest.fixture(scope="class")
    def ep(self) -> str:
        assert _ENTRYPOINT.exists(), "docker-entrypoint.sh must exist"
        return _ENTRYPOINT.read_text()

    def test_has_shebang(self, ep):
        assert ep.startswith("#!/")

    def test_set_e(self, ep):
        """Must use `set -e` for fail-fast behaviour."""
        assert "set -e" in ep

    def test_discovers_sdk_path(self, ep):
        """Must dynamically discover the installed SDK path."""
        assert "sdk" in ep.lower()
        assert "python" in ep

    def test_starts_webview_server(self, ep):
        assert "webview_server" in ep

    def test_forwards_args(self, ep):
        """Must forward extra arguments to the server."""
        assert '"$@"' in ep or '"${@}"' in ep


# ---------------------------------------------------------------------------
# docker-publish.yml workflow
# ---------------------------------------------------------------------------


class TestDockerPublishWorkflow:
    """Validate the Docker publish GitHub Actions workflow."""

    @pytest.fixture(scope="class")
    def wf(self) -> str:
        assert _WORKFLOW.exists(), ".github/workflows/docker-publish.yml must exist"
        return _WORKFLOW.read_text()

    def test_triggers_on_release(self, wf):
        assert "release" in wf
        assert "published" in wf

    def test_pushes_to_ghcr(self, wf):
        assert "ghcr.io" in wf

    def test_multi_arch(self, wf):
        """Must build for both amd64 and arm64."""
        assert "linux/amd64" in wf
        assert "linux/arm64" in wf

    def test_uses_buildx(self, wf):
        assert "buildx" in wf.lower()

    def test_latest_tag_on_stable(self, wf):
        """Stable releases should produce a :latest tag."""
        assert "latest" in wf

    def test_packages_write_permission(self, wf):
        """Needs packages: write to push to GHCR."""
        assert "packages: write" in wf

    def test_uses_pinned_actions(self, wf):
        """All uses: lines must pin to a full commit SHA."""
        uses_lines = [l.strip() for l in wf.splitlines() if l.strip().startswith("uses:")]
        for line in uses_lines:
            assert re.search(r"@[0-9a-f]{40}", line), f"Action not pinned to SHA: {line}"

    def test_build_cache(self, wf):
        """Must use GHA layer cache for faster rebuilds."""
        assert "cache-from" in wf and "cache-to" in wf

    def test_oci_metadata(self, wf):
        """Must use metadata-action for OCI labels and tags."""
        assert "metadata-action" in wf
