# Contributing to WolfPack NMS

Thanks for improving WolfPack NMS.

## Engineering principles

Changes should preserve the project's evidence-oriented behavior:

- distinguish current state from recorded evidence
- record observer/source context where it matters
- avoid manufacturing historical data
- alert on meaningful state transitions rather than repeatedly on unchanged conditions
- preserve upgrade compatibility where practical
- fail clearly rather than silently claiming unsupported observations

## Development setup

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
export WOLFPACK_NMS_DB="$PWD/dev-wolfpack.db"
python run.py
```

Use a disposable development database.

## Before submitting a change

1. Confirm Python files compile.
2. Exercise the changed workflow against lab/test systems.
3. Verify `/api/health` still returns healthy.
4. Confirm migrations work against an existing test database when schema changes are involved.
5. Review `git diff` and `git status` for credentials, databases, evidence, logs, or unrelated changes.
6. Update `README.md`/`HOWTO.md` when behavior or operator workflow changes.

Basic compile check:

```bash
python -m compileall -q wolfpack_nms run.py
```

## Security

Do not submit real credentials, private keys, operational databases, or sensitive network evidence. See `SECURITY.md`.
