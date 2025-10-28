CodeVul Dataset Toolkit
=======================

This repository curates multiple open-source vulnerability corpora and provides
tooling to normalise, deduplicate, and analyse them in a consistent format. The
primary datasets include CrossVul, JaConTeBe, MegaVul, MSR, PrimeVul, SVEN, and
several auxiliary benchmarks. Normalised exports power downstream research,
while signature and statistics reports support quality checks and curation.

Features
--------
- Canonical CSV exports produced from heterogeneous dataset formats.
- Deterministic per-sample signatures for duplicate detection.
- CWE coverage statistics and category roll-ups derived from `collect.json`.
- Single-entry CLI (`python main.py`) that orchestrates the full pipeline.

Environment
-----------
- Python 3.12+ (managed with `uv venv` in this repository).
- Dataset-specific dependencies are kept minimal; optional `pyarrow` enables
  Juliet statistics.

Quick Start
-----------
1. Activate the virtual environment (once created via `uv venv`):
   ```bash
   source .venv/bin/activate
   ```
2. Normalize, deduplicate, and compute stats for all datasets:
   ```bash
   python main.py --dataset all
   ```
   Add `--force-normalize` or `--force-signatures` to rebuild existing outputs.
3. Inspect generated artifacts:
   - Normalised CSVs in `standardized/`.
   - Signature manifests in `signatures/`.
   - CWE counts in `cwe_counts.json`.
   - Category summaries in `category_summary_level*.csv`.

CLI Reference
-------------
```
python main.py [options]
  --dataset NAME        Target dataset(s); repeatable. Use "all" for every dataset.
  --limit N             Cap the number of rows emitted during normalization.
  --signature-dir DIR   Destination for signature CSVs (default: signatures/).
  --force-normalize     Rebuild normalized CSVs even if they already exist.
  --force-signatures    Rebuild signature CSVs even if they already exist.
  --verbose             Enable DEBUG logging for troubleshooting.
```

Supporting Scripts
------------------
- `scripts/normalize_datasets.py`: dataset-specific normalizers (mostly invoked
  via `main.py`).
- `scripts/signatures.py`: standalone signature generation if required.
- `scripts/cwe_stats.py`: CWE statistics (used by the pipeline).
- `scripts/category_summary.py`: category-level aggregation based on
  `collect.json`.

Repository Layout
-----------------
- `crossvul/`, `JaConTeBe/`, `megavul/`, etc.: raw dataset sources.
- `src/dataset/`: normalization modules for each corpus.
- `src/signature.py`: code canonicalisation and hashing utilities.
- `standardized/`: canonicalised CSV exports.
- `signatures/`: per-row signature manifests.
- `scripts/`: command-line helpers and analytics.

Contributing
------------
Follow the dataset naming and metadata conventions outlined in
`user_instructions`. When adding new samples:
- Update the corresponding dataset manifest (e.g., `crossvul/metadata.json`).
- Regenerate the affected normalized CSV and signature files via `main.py`.
- Refresh statistics and summaries to keep downstream analyses in sync.

License
-------
This repository aggregates datasets with their respective upstream licenses.
Refer to each dataset directory for attribution details.
