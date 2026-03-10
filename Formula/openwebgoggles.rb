# typed: false
# frozen_string_literal: true

# Homebrew formula for openwebgoggles.
#
# Install from the techtoboggan tap:
#   brew tap techtoboggan/tap
#   brew install openwebgoggles
#
# This formula is auto-updated by .github/workflows/homebrew-update.yml
# when a new GitHub Release is published.

class Openwebgoggles < Formula
  include Language::Python::Virtualenv

  desc "Browser-based human-in-the-loop UI panels for AI coding agents"
  homepage "https://github.com/techtoboggan/openwebgoggles"
  url "https://files.pythonhosted.org/packages/source/o/openwebgoggles/openwebgoggles-0.15.0.tar.gz"
  sha256 "PLACEHOLDER_SHA256_UPDATED_BY_WORKFLOW"
  license "Apache-2.0"
  head "https://github.com/techtoboggan/openwebgoggles.git", branch: "main"

  bottle do
    root_url "https://ghcr.io/v2/techtoboggan/tap/blobs/sha256:"
    # Bottle hashes added automatically by the Homebrew CI after each release
  end

  depends_on "python@3.12"

  # Core runtime dependencies (kept in sync with pyproject.toml)
  resource "websockets" do
    url "https://files.pythonhosted.org/packages/source/w/websockets/websockets-14.2.tar.gz"
    sha256 "0ac0b44cf530be0c7b5e99a60ee00dec5e78f7ca5cb3fc4bc78db4e42dcc02f6"  # pragma: allowlist secret
  end

  resource "PyNaCl" do
    url "https://files.pythonhosted.org/packages/source/P/PyNaCl/PyNaCl-1.5.0.tar.gz"
    sha256 "8ac7448f09ab85811607bdd21ec2464495ac8b7c66d2b1d1f5a8ca2cb63befbf"  # pragma: allowlist secret
  end

  # mcp and its transitive dependencies
  resource "mcp" do
    url "https://files.pythonhosted.org/packages/source/m/mcp/mcp-1.9.4.tar.gz"
    sha256 "PLACEHOLDER_MCP_SHA256"
  end

  def install
    # Install into a virtualenv so we don't pollute the system Python
    virtualenv_install_with_resources
  end

  test do
    # Verify the CLI entry point responds to --help without errors
    assert_match "usage", shell_output("#{bin}/openwebgoggles --help 2>&1", 0)
    # Verify the version output (exits 0)
    output = shell_output("#{bin}/openwebgoggles status 2>&1")
    assert_match(/openwebgoggles|version/i, output)
  end
end
