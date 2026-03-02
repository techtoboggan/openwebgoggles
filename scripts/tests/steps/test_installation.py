"""Step definitions for installation.feature."""

from __future__ import annotations

import os
import sys
from unittest import mock

import pytest
from pytest_bdd import given, parsers, scenario, then, when

sys.path.insert(0, os.path.join(os.path.dirname(__file__), "..", ".."))

import mcp_server  # noqa: E402, I001

pytestmark = pytest.mark.bdd


@scenario("../features/installation.feature", "Detect version from installed package metadata")
def test_detect_installed():
    pass


@scenario("../features/installation.feature", "Return unknown when package is not installed")
def test_detect_not_installed():
    pass


@scenario("../features/installation.feature", "Fresh version read bypasses importlib cache")
def test_fresh_read_bypass():
    pass


@scenario("../features/installation.feature", "Fresh version read scans site-packages as fallback")
def test_fresh_read_scan():
    pass


class _Ctx:
    pass


@pytest.fixture
def ctx():
    return _Ctx()


@given("openwebgoggles is installed via pip")
def package_installed(ctx):
    ctx.installed = True


@when("get_installed_version_info is called")
def call_get_version(ctx):
    if getattr(ctx, "installed", False):
        mock_dist = mock.MagicMock()
        mock_dist.metadata = {"Version": "0.12.2"}
        mock_dist._path = "/fake/site-packages/openwebgoggles-0.12.2.dist-info"
        with mock.patch("importlib.metadata.distribution", return_value=mock_dist):
            ctx.version, ctx.path = mcp_server._get_installed_version_info()
    else:
        with mock.patch(
            "importlib.metadata.distribution",
            side_effect=mcp_server.importlib.metadata.PackageNotFoundError,
        ):
            ctx.version, ctx.path = mcp_server._get_installed_version_info()


@then("it should return the installed version string")
def assert_version_string(ctx):
    assert ctx.version == "0.12.2"


@then("it should return the dist-info path")
def assert_dist_path(ctx):
    assert ctx.path is not None


@given("openwebgoggles is not installed")
def package_not_installed(ctx):
    ctx.installed = False


@then("it should return unknown")
def assert_unknown(ctx):
    assert ctx.version == "unknown"


@then("the path should be None")
def assert_path_none(ctx):
    assert ctx.path is None


@given(parsers.parse('a dist-info directory exists with METADATA version "{version}"'))
def dist_info_with_version(ctx, tmp_path, version):
    dist_dir = tmp_path / f"openwebgoggles-{version}.dist-info"
    dist_dir.mkdir()
    (dist_dir / "METADATA").write_text(f"Metadata-Version: 2.1\nName: openwebgoggles\nVersion: {version}\n")
    ctx.dist_info_path = dist_dir
    ctx.expected_version = version


@when("read_version_fresh is called with the dist-info hint")
def call_fresh_read_with_hint(ctx):
    ctx.result = mcp_server._read_version_fresh(dist_info_hint=ctx.dist_info_path)


@then(parsers.parse('it should return "{version}"'))
def assert_version(ctx, version):
    assert ctx.result == version


@then("it should read directly from disk")
def assert_disk_read(ctx):
    # Verified by the fact that we got the correct version from a real file
    assert ctx.result == ctx.expected_version


@given("the dist-info hint path no longer exists")
def hint_path_gone(ctx, tmp_path):
    ctx.stale_hint = tmp_path / "gone-dist-info"
    ctx.site_packages = tmp_path / "site-packages"


@given("a dist-info directory exists in site-packages")
def dist_info_in_site_packages(ctx):
    ctx.site_packages.mkdir(parents=True)
    dist_dir = ctx.site_packages / "openwebgoggles-3.0.0.dist-info"
    dist_dir.mkdir()
    (dist_dir / "METADATA").write_text("Metadata-Version: 2.1\nName: openwebgoggles\nVersion: 3.0.0\n")
    ctx.expected_version = "3.0.0"


@when("read_version_fresh is called without a hint")
def call_fresh_read_scan(ctx):
    with mock.patch("mcp_server._get_site_packages_dirs", return_value=[ctx.site_packages]):
        ctx.result = mcp_server._read_version_fresh(dist_info_hint=ctx.stale_hint)


@then("it should find the version via site-packages scan")
def assert_site_packages_scan(ctx):
    assert ctx.result == ctx.expected_version
