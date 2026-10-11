# Contributing

This is a personal portfolio repository. Suggestions via issues are welcome; pull requests from others are not expected.

## Local loop

```bash
python -m venv .venv && . .venv/bin/activate
pip install -e ".[dev]"
ruff check . && ruff format .
pytest -q
aauth gate
python scripts/render_docs.py
```

## Rules

- Never commit private keys, `.env`, or real tenant identifiers
- Never import `aauth.naive` from default paths
- Keep docs free of dates and placeholder words (the usual unfinished markers)
- Report only numbers from real local runs
