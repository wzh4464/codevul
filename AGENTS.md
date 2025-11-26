# Repository Guidelines

## Project Structure & Module Organization
This dataset repository aggregates multiple vulnerability corpora. `crossvul/` is arranged by CWE then language; each sample is stored as `bad_*` or `good_*` and cross-referenced in `metadata.json`, `generic_messages.list`, and `commits.list`. `cvefixes/CVEFixes.csv` lists CVE metadata sourced from CVEfixes. `devign/` contains `ffmpeg.csv`, `qemu.csv`, and `vulnerables.json` for model training benchmarks. `megavul/` holds the normalized MegaVul dump (prefer editing the uncompressed `megavul/` subfolder; leave the legacy archives untouched). `ReVeal/` provides `function.json` and `non-vulnerables.json`. Root-level CSV/zip files are canonical exports; regenerate them deliberately.

The `cvefixes/` tree ships upstream CVEfixes v1.0.8 under `CVEfixes_v1.0.8/Data/`. The normalization process uses a SQLite database automatically created from the SQL dump (`CVEfixes_v*.sql.gz`). Data is extracted via SQL queries that join file changes with CWE classifications, filtering specifically for C/C++/Java samples. Use `python scripts/normalize_datasets.py` to emit per-dataset canonical CSVs (`standardized/*.csv`) with the columns: `cwe`, `code_before`, `code_after`, `commit_url`, `language`. Pass `--limit N` to generate a capped sample (useful for the larger corpora). All downstream analyses should rely on these normalized exports rather than heterogeneous raw formats.

## Build, Test, and Development Commands
This is a data-first repository; light-weight validation is expected before every change. Example checks:

```bash
python -m json.tool crossvul/metadata.json > /dev/null
jq '.[].files | length' crossvul/metadata.json | head
python - <<'PY'
import csv
with open('cvefixes/CVEFixes.csv', newline='') as fh:
    next(csv.reader(fh))  # ensure header present
PY
```

Run commands from the repository root so relative paths resolve. Commit refreshed aggregates only after spot-checking diffs.

## Environment & Dependency Management
Python tooling is managed through `uv`. Activate the shared virtual environment with `source .venv/bin/activate` (created via `uv venv`). Install or update dependencies with `uv add <package>` so `pyproject.toml` and `uv.lock` stay in sync; avoid `pip install` inside the repo.

## Coding Style & Naming Conventions
Preserve the original formatting of code samples—do not auto-format or strip comments. Name new snippets with the existing pattern (`bad_<id>_<variant>`, `good_<id>_<variant>`) and register them in `metadata.json`. New CSV columns require coordinator approval and must be appended to the header row. Keep JSON keys snake_case and strings UTF-8 encoded.

## Testing Guidelines
Before raising a PR, confirm that every new sample appears in the appropriate manifest: update `crossvul/metadata.json`, append commit IDs to `commits.list`, and refresh any affected message lists. Use `jq` or ad-hoc Python scripts to assert that each `bad_*` entry has a matching `good_*` entry. For CSV updates, run a quick duplicate scan (`cut -d, -f1 cvefixes/CVEFixes.csv | sort | uniq -d`) to guard against conflicting CVE IDs.

## Commit & Pull Request Guidelines
Use short, imperative commit subjects prefixed with the touched dataset (e.g., `crossvul: add CWE-79 php sample`). Combine related file updates into single commits so metadata and artifacts stay synchronized. PRs should summarise the data source, validation steps, and any scripts used; link to upstream advisories or CVEs when available. Include sample counts in the description and flag any regenerated archives so reviewers can focus on material changes.
