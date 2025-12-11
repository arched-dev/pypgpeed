<!-- CODEX_MAINTENANCE_BEGIN TOOLKIT RULES (PYTHON) -->
# AGENTS.python.md – Automaintian Python maintenance

These instructions are written for Codex when it is working inside a Python
service or application. They are deliberately conservative.

## Global rules

- Work only inside the current workspace root.
- Never touch files outside the project root.
- Completely ignore and never modify:

  - Any hidden folders (names starting with `.`), such as:
    `.git`, `.github`, `.idea`, `.vscode`, `.ruff_cache`, `.pytest_cache`,
    `.qodo`, `.cache`, `.codex`, `.codex-maint-venv`, `.ipynb_checkpoints`,
    `.local`, `.uv_cache`, `.uv-cache`.
  - Build and dependency artefacts:
    `node_modules`, `build`, `dist`, `coverage-js`, `htmlcov`, `__pycache__`.
  - Virtual environment folders:
    `.venv`, `venv`, `env`, `.env`.
  - Large log or archive folders:
    `logs`, `backups`, `archive`, `Archive`.

- Do not run database migrations or destructive SQL.
- Do not call external services that could mutate production data.
- Always assume that a behavioural change is dangerous unless it is trivially safe.

### Python plus frontend

Many of these projects combine a Flask or API backend with a frontend in
`frontend`, `src`, or similar.

- Treat large React or SPA frontends as **read only**.
- It is acceptable to read JS/TS/HTML to understand how APIs are used.
- You may apply small, obviously safe fixes to HTML/JS that are tightly coupled
  to Flask templates, but do not rework SPA routing, state management, or build tooling.

### Virtual environments

- Prefer using an existing virtual environment in the project if it exists
  (`.venv`, `venv`, `env`, `.env`).
- If you need to create a virtual environment temporarily:

  - Name it something unique that does not clash with existing folders, such as
    `.codex-maint-venv-<random>`.
  - Use it only for the minimum work required (for example running tests).
  - Remove the virtual environment directory entirely before finishing.

## Outputs to maintain

In every phase you should:

- Keep `suggestions.md` updated with:

  - Safe refactor ideas.
  - Readability improvements.
  - Test additions or test structure improvements.

- Keep `enhancements.md` updated with:

  - Larger, future facing changes.
  - Architecture or performance ideas.
  - New feature suggestions.

If the files do not exist, create them in the project root.

## Phases

### 1. Prep

- Quickly scan the project tree (excluding ignored folders).
- Identify:

  - Main application entrypoints.
  - Configuration files.
  - Tests and fixtures.
  - Templates and static assets.

- Produce a plan for:

  - Quality work (formatting, linting, simple refactors).
  - Tests to run.
  - Read only bughunt focus areas.
  - Versioning and changelog updates.

### 2. Quality & cleanup

- Format Python code using the project standard tools:

  - Prefer `black` if configured.
  - Use `ruff` for linting and, where appropriate, for simple fixes such as
    unused imports or obvious style violations.

- Minor code improvements:

  - Extract repeated literals or snippets where this is clearly non breaking.
  - Improve variable names and docstrings where intent is clear.
  - Tidy error handling and logging without changing behaviour.

- Never:

  - Change public function or method signatures.
  - Change database schema or ORM models in a way that alters stored data.
  - Re order logic in a way that might change semantics.

- Anything that smells like it might break production goes into `suggestions.md`
  or `enhancements.md` instead of being changed in code.

### 3. Tests

- Detect how tests are run (for example `pytest`, `python -m pytest`, `tox`).

- Run the lightest reasonable suite:

  - Prefer unit and integration tests.
  - Avoid very heavy or long running tests by default.

- Fix only trivial issues, such as:

  - Obvious typos in test names or assertions.
  - Broken imports in tests.

- Do not change production code purely to satisfy a test if you are unsure of
  the intended behaviour. Instead, document:

  - The failing test.
  - Why it fails.
  - A candidate fix.

  in `suggestions.md`.

### 4. Bughunt (read only)

- Use static analysis and code inspection to flag:

  - Obvious bugs and edge cases.
  - Unsafe error handling or bare exceptions.
  - Concurrency and async issues.
  - Security concerns (unsafe deserialisation, obvious injection risks, etc).

- Do not change any code in this phase.

- For each issue, record in `suggestions.md` or `enhancements.md`:

  - File and line range.
  - Short description.
  - Why it is risky.
  - An outline of a safe remediation.

### 5. Versioning & changelog

- If the project uses `pyproject.toml` or `setup.cfg`:

  - Infer whether a patch, minor, or major bump is appropriate from the
    cumulative changes in this maintenance run.
  - Propose a version bump and, if it is consistent with existing practice,
    apply it.

- Update `CHANGELOG.md` or equivalent:

  - Group changes under a heading for the new version.
  - Summarise key changes from the quality, tests, and bughunt phases.

- If no changelog exists, you may create one and add an entry describing this
  maintenance run.

Always prefer underselling changes rather than overstating them. The maintainer
should be able to read the changelog and understand exactly what Automaintian did.
<!-- CODEX_MAINTENANCE_END TOOLKIT RULES (PYTHON) -->

