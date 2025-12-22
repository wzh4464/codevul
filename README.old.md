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

Data Processing Pipeline
-----------------------
The toolkit implements a multi-stage pipeline that transforms raw vulnerability
datasets into clean, deduplicated benchmarks. See [docs/PIPELINE.md](docs/PIPELINE.md)
for the complete pipeline documentation.

**Pipeline Stages:**
1. **Standardization** (`scripts/normalize_datasets.py`) - Convert datasets to unified CSV format
2. **Signature Generation** (`scripts/signatures.py`) - Create content hashes for deduplication
3. **Deduplication** (`scripts/clean_duplicates.py`) - Remove duplicate entries
4. **Benchmark Creation** (`scripts/create_benchmark.py`) - Merge into unified JSON
5. **Filtering** (`scripts/filter_benchmark.py`) - Select representative samples
6. **Clustering** (`scripts/cluster_benchmark.py`) - ML-based sample selection
7. **Analysis** (`scripts/analyze_cwe.py`) - Statistical analysis and reporting

Supporting Scripts
------------------

### Core Pipeline Scripts
- `scripts/normalize_datasets.py`: Dataset-specific normalizers (invoked via `main.py`)
- `scripts/signatures.py`: Standalone signature generation
- `scripts/clean_duplicates.py`: Cross-dataset deduplication
- `scripts/create_benchmark.py`: Unified benchmark creation
- `scripts/filter_benchmark.py`: Stratified sample selection (10 per CWE)
- `scripts/cluster_benchmark.py`: Embedding-based clustering and selection

### Analysis & Statistics
- `scripts/analyze_cwe.py`: Unified CWE analysis tool
  - Simple counting mode: `python scripts/analyze_cwe.py input.jsonl`
  - Detailed analysis: `python scripts/analyze_cwe.py input.jsonl --detailed`
  - CSV export: `python scripts/analyze_cwe.py input.jsonl -o stats.csv`
- `scripts/cwe_stats.py`: Comprehensive CWE statistics
- `scripts/category_summary.py`: Category-level aggregation
- `scripts/analyze_cwe_stats.py`: Advanced CWE analytics

### Utilities (Deprecated - use scripts/ versions)
- `scripts/json_to_jsonl.py`: JSON to JSONL conversion
- `scripts/count_cwe.py`: Simple CWE counting (superseded by `analyze_cwe.py`)

Repository Layout
-----------------
- `crossvul/`, `JaConTeBe/`, `megavul/`, etc.: raw dataset sources.
- `src/dataset/`: normalization modules for each corpus.
- `src/signature.py`: code canonicalisation and hashing utilities.
- `src/utils/`: shared utility modules for JSON/CSV I/O, CWE processing, logging, etc.
- `standardized/`: canonicalised CSV exports.
- `signatures/`: per-row signature manifests.
- `clean/`: deduplicated standardized data and signatures.
- `scripts/`: command-line helpers and analytics.
- `docs/`: documentation including the complete pipeline guide.

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
