# Contributing

Thanks for helping improve the project.

## Development setup

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r requirements.txt
python -m pip install -r requirements-dev.txt
```

## Pull request expectations

- keep changes focused and easy to review
- add or update tests for behavior changes
- avoid introducing unnecessary dependencies
- document user-facing changes in the README

## Quality bar

- make sure the test suite passes locally before opening a PR
- prefer small, readable functions and clear naming
- keep scanning logic safe and permission-aware
