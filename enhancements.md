# Enhancements

- Adopt `pyproject.toml` with consolidated metadata (version, dependencies, optional dev tools) to reduce duplication between `setup.py` files and enable modern packaging workflows.
- Add lightweight CI (e.g., GitHub Actions) running lint and pytest to catch regressions and verify packaging builds.
- Replace the custom `cx_Freeze` setup with a reusable build script that shares the same version constant as the main package to avoid drift between distributable targets.
