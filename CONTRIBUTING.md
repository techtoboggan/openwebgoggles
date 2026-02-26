# Contributing to OpenWebGoggles

Thank you for your interest in contributing.

## Using OpenWebGoggles (Quick Start)

If you just want to use it — not develop on it:

```bash
pip install openwebgoggles
openwebgoggles init claude    # or: openwebgoggles init opencode
```

Restart your editor. Done. See the [README](README.md) for the full API, usage patterns, and manual setup options.

## Development Setup

For working on OpenWebGoggles itself:

1. Clone and enter the repo:

```bash
git clone https://github.com/techtoboggan/openwebgoggles.git
cd openwebgoggles
```

2. Create a virtual environment inside `scripts/` (this is where the Python code lives):

```bash
cd scripts
python3 -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
```

3. Install runtime + dev dependencies:

```bash
pip install -r requirements.txt
pip install -e ".[dev]"
```

The editable install (`-e`) lets you run `openwebgoggles` as a CLI command that reflects your local changes.

4. Install pre-commit hooks (runs ruff lint + format on every commit):

```bash
pre-commit install
```

4. Verify everything works:

```bash
cd ..  # back to repo root
scripts/.venv/bin/python -m pytest scripts/tests/ -v
```

## Running Tests

From the repo root:

```bash
scripts/.venv/bin/python -m pytest scripts/tests/ -v
```

Tests are tagged with OWASP Top 10, MITRE ATT&CK, and OWASP LLM Top 10 markers for traceability. Run a specific category:

```bash
# Just the OWASP injection tests
scripts/.venv/bin/python -m pytest scripts/tests/ -v -m owasp_a03

# Just the LLM prompt injection tests
scripts/.venv/bin/python -m pytest scripts/tests/ -v -m llm01
```

## Linting

```bash
ruff check scripts/
ruff format --check scripts/
```

## Project Structure

```
scripts/          Python server, MCP server, crypto, security gate, shell helpers
  tests/          pytest test suite
assets/
  sdk/            Client-side JavaScript SDK
  apps/dynamic/   Built-in dynamic UI renderer
  template/       App scaffold template
examples/         Demo apps (approval-review, security-qa)
references/       Data contract, SDK API, integration guide docs
```

## Making Changes

1. Create a branch from `main`
2. Make your changes
3. Ensure tests pass and linting is clean
4. Submit a pull request

## Releasing

We publish to [PyPI](https://pypi.org/project/openwebgoggles/) via GitHub Releases using [Trusted Publishers](https://docs.pypi.org/trusted-publishers/) (OIDC — no API tokens).

### Versioning

- We follow [Semantic Versioning](https://semver.org/): `MAJOR.MINOR.PATCH`
- Git tags use the `v` prefix: `v0.1.0`, `v0.2.0`, `v1.0.0`
- The version in `pyproject.toml` must match the tag (without the `v`). The publish workflow validates this automatically and fails if they're out of sync.

### Release Process

1. **Bump the version** in `pyproject.toml`:

```python
version = "0.2.0"  # was "0.1.0"
```

2. **Update CHANGELOG.md** — add a new section following the [Keep a Changelog](https://keepachangelog.com/) format:

```markdown
## [0.2.0] - 2026-03-15

### Added
- Whatever you added

### Changed
- Whatever you changed

### Fixed
- Whatever you fixed
```

3. **Commit and push**:

```bash
git add pyproject.toml CHANGELOG.md
git commit -m "Bump version to 0.2.0"
git push origin main
```

4. **Tag the release**:

```bash
git tag -a v0.2.0 -m "v0.2.0"
git push origin v0.2.0
```

5. **Create the GitHub Release** (this triggers the publish workflow):

```bash
gh release create v0.2.0 \
  --title "v0.2.0 — Short Description" \
  --notes "What changed in this release."
```

6. **Verify** — the [Publish to PyPI](https://github.com/techtoboggan/openwebgoggles/actions/workflows/publish.yml) workflow should go green within a minute. Check that the new version appears:

```bash
pip index versions openwebgoggles
```

### What the Workflow Does

The `.github/workflows/publish.yml` workflow:

1. Extracts the version from `pyproject.toml` and compares it to the git tag — fails if they don't match
2. Builds the sdist and wheel via `python -m build`
3. Publishes to PyPI via OIDC trusted publishers (no API tokens needed)
4. Generates and uploads digital attestations

### Version Bumping Cheat Sheet

| Change | Example | When |
|--------|---------|------|
| Patch | `0.1.0` → `0.1.1` | Bug fixes, docs, test changes |
| Minor | `0.1.0` → `0.2.0` | New features, backwards-compatible |
| Major | `0.1.0` → `1.0.0` | Breaking changes to the API |

## Security

If you discover a security vulnerability, please report it privately rather than opening a public issue. See the security architecture in the README for context on the defense layers.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
