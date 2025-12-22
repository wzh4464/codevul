# CodeVul Benchmark Pipeline

A modular pipeline for processing vulnerability datasets and generating standardized benchmarks.

## Quick Start

```bash
# Install dependencies
uv sync

# Run complete pipeline
python run.py pipeline

# Or run individual steps
python run.py normalize --dataset juliet --limit 100
python run.py clean
python run.py transform
python run.py sample
```

## Directory Structure

```
├── config/pipeline.yaml  # Configuration
├── datasets/             # Raw data (gitignored)
├── results/              # Pipeline outputs (gitignored)
│   ├── normalized/       # Step 1: Standardized CSVs
│   ├── cleaned/          # Step 2: Filtered CSVs
│   ├── benchmark/        # Step 3: benchmark.json
│   └── samples/          # Step 4: Sample files
├── src/                  # Source modules
│   ├── cleaning/         # Filtering steps
│   ├── dataset/          # Dataset normalizers
│   ├── pipeline/         # Orchestration
│   └── transform/        # Transformation logic
├── scripts/              # One-off utilities
└── run.py                # Main entry point
```

## Pipeline Stages

### 1. Normalize
Convert raw datasets to standard CSV (cwe, code_before, code_after, commit_url, language)

### 2. Clean
Apply mandatory filters:
- Language (C/C++, Java only)
- CWE validation
- Code validation (non-empty, different before/after)
- URL validation (optional)
- Deduplication (placeholder)

### 3. Transform
- Map CWE → CWD (Code Weakness Dictionary)
- Extract code structure (class/function names)
- Extract CVE IDs from CVEfixes
- Apply clustering for large groups (>300 entries)
- Generate benchmark.json

### 4. Sample
Generate one sample per dataset for inspection

## Configuration

Edit `config/pipeline.yaml`:

```yaml
datasets:
  active:
    - cvefixes
    - juliet
    - msr
    - megavul
    - primevul
    - sven
    - jacontebe

pipeline:
  clean:
    language_filter:
      allowed: ['c/c++', 'java']
  
  transform:
    clustering:
      max_samples_per_group: 300
      method: 'kmeans'  # or 'stratified'
```

## Commands

```bash
# Normalize specific dataset
python run.py normalize --dataset cvefixes --limit 1000

# Clean all normalized data
python run.py clean

# Transform to benchmark
python run.py transform

# Generate samples
python run.py sample

# Run everything
python run.py pipeline --limit 500
```

## Output Format

### Benchmark JSON

```json
{
  "c/c++": {
    "CWD-1059": [
      {
        "benign_code": {
          "context": "fixed code",
          "class": "ClassName",
          "func": "function code"
        },
        "vulnerable_code": {
          "context": "vulnerable code",
          "class": "ClassName",
          "func": "function code"
        },
        "source": "dataset_name",
        "commit_url": "https://github.com/...",
        "CWE": "CWE-22",
        "other_CWEs": [],
        "other_CWDs": [],
        "CVE": "CVE-2023-12345"
      }
    ]
  }
}
```

## Key Features

- **Modular**: Each stage is independent
- **Configurable**: All settings in YAML
- **Scalable**: Streaming processing, parallel normalization
- **Quality**: Multiple validation layers
- **Reproducible**: Consistent output format

## Common Issues

### CWE Not Mapping
Ensure CWE format is correct. Pipeline normalizes:
- `cwe-022` → `CWE-22`
- Leading zeros removed

### All Data Filtered
Check language field is set to `c`, `c++`, `cpp`, or `java`

### CVE Extraction Skipped
Ensure CVEfixes dataset exists at `datasets/cvefixes/CVEfixes_v*/Data/*.sql.gz`

## Development

### Adding a Dataset

1. Create normalizer in `src/dataset/your_dataset.py`
2. Register in `src/dataset/__init__.py`: `NORMALIZERS['your_dataset'] = normalize_your_dataset`
3. Add to `config/pipeline.yaml`

### Adding a Cleaning Step

1. Create class in `src/cleaning/your_step.py` extending `CleaningStep`
2. Add to pipeline in `src/pipeline/clean.py`

## Environment

```bash
# Optional: GitHub token for URL validation
export GITHUB_TOKEN=your_token_here
```

## Performance

Typical times (varies by hardware/dataset size):
- Normalize: 1-30 min/dataset
- Clean: 1-5 min
- Transform: 1-5 min (+ CVEfixes parsing)
- Sample: <1 sec

## Troubleshooting

```bash
# Check logs
tail -f results/pipeline.log

# Validate outputs
wc -l results/cleaned/*.csv
python -c "import json; print(list(json.load(open('results/benchmark/benchmark.json')).keys()))"

# Reset
rm -rf results/
python run.py pipeline
```

## Old README

Previous documentation backed up to `README.old.md`
