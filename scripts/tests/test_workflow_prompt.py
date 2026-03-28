"""
Tests for the openwebgoggles_workflow MCP prompt.

Covers:
  - Returns a non-empty string
  - Mentions openwebgoggles_read (MCP Apps mode workflow step)
  - Mentions openwebgoggles_close (REQUIRED rule)
  - Mentions 'attention' (for Remind Agent handling)
"""

from __future__ import annotations

import os
import sys


sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from mcp_server import openwebgoggles_workflow


class TestWorkflowPrompt:
    def test_returns_non_empty_string(self):
        """openwebgoggles_workflow() returns a non-empty string."""
        result = openwebgoggles_workflow()
        assert isinstance(result, str)
        assert len(result.strip()) > 0

    def test_mentions_openwebgoggles_read(self):
        """Workflow prompt mentions openwebgoggles_read for MCP Apps mode."""
        result = openwebgoggles_workflow()
        assert "openwebgoggles_read" in result

    def test_mentions_openwebgoggles_close(self):
        """Workflow prompt mentions openwebgoggles_close as a required step."""
        result = openwebgoggles_workflow()
        assert "openwebgoggles_close" in result

    def test_mentions_attention(self):
        """Workflow prompt mentions 'attention' for Remind Agent handling."""
        result = openwebgoggles_workflow()
        assert "attention" in result
