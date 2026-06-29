# Contributing to Privacy-First PII Redactor

Thank you for considering a contribution! Here is how to get started.

## Development setup

```bash
git clone https://github.com/your-org/privacy-pii-redactor
cd privacy-pii-redactor
pip install -e ".[dev]"
```

## Running tests

```bash
# Fast (regex-only, no ML deps)
pytest tests/ -v

# With coverage
pytest tests/ --cov=pii_redactor --cov-report=term-missing

# Single file
pytest tests/test_detection.py -v
```

## Code style

We use `ruff` for linting:

```bash
ruff check src/ tests/
ruff format src/ tests/
```

## Pull request checklist

- [ ] Tests pass locally (`pytest tests/`)
- [ ] New behaviour is covered by tests
- [ ] Logs never contain raw PII values
- [ ] No secrets committed to source control
- [ ] `ruff check` passes
- [ ] Type hints present on new public APIs

## Reporting bugs

Open a GitHub issue with:
1. Python version
2. Minimal reproducible example
3. Expected vs. actual behaviour

Do **not** include real PII in bug reports. Use synthetic data.
