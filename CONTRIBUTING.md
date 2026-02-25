# Contributing to OpenWebGoggles

Thank you for your interest in contributing.

## Development Setup

1. Clone the repository:

```bash
git clone https://github.com/techtoboggan/openwebgoggles.git
cd openwebgoggles
```

2. Create and activate a virtual environment:

```bash
cd scripts
python -m venv .venv
source .venv/bin/activate  # or .venv\Scripts\activate on Windows
```

3. Install dependencies:

```bash
pip install -r requirements.txt
pip install pytest pytest-asyncio ruff
```

## Running Tests

From the repo root:

```bash
scripts/.venv/bin/python -m pytest scripts/tests/ -v
```

All 378 tests should pass. Tests are tagged with OWASP and MITRE ATT&CK markers for traceability.

## Linting

```bash
ruff check scripts/
ruff format --check scripts/
```

## Project Structure

```
scripts/          Python server, crypto, security gate, shell helpers
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

## Security

If you discover a security vulnerability, please report it privately rather than opening a public issue. See the security architecture in the README for context on the defense layers.

## License

By contributing, you agree that your contributions will be licensed under the Apache License 2.0.
