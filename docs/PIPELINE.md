# Data Processing Pipeline

This document describes the complete data processing pipeline for the codevul dataset, from raw datasets to clean, deduplicated benchmark data.

## Overview

The pipeline processes multiple vulnerability datasets (CrossVul, CVEfixes, MegaVul, etc.) through standardization, deduplication, and benchmark creation stages to produce a unified, high-quality dataset for vulnerability analysis.

## Pipeline Stages

```
┌─────────────────────────────────────────────────────────────────────────┐
│                          STAGE 1: RAW DATASETS                          │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
              ┌─────▼────┐    ┌────▼────┐    ┌────▼────┐
              │ CrossVul │    │CVEfixes │    │ MegaVul │  ... and more
              └──────────┘    └─────────┘    └─────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                    STAGE 2: STANDARDIZATION                             │
│                  scripts/normalize_datasets.py                          │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    Standardized Format (CSV):
                    ┌────────────────────────────────┐
                    │ • cwe                          │
                    │ • code_before                  │
                    │ • code_after                   │
                    │ • commit_url                   │
                    │ • language                     │
                    └────────────────────────────────┘
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │   standardized/*.csv          │
                    │   (per-dataset CSV files)     │
                    └───────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                     STAGE 3: SIGNATURE GENERATION                       │
│                      scripts/signatures.py                              │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                Generate content-based signatures
                for duplicate detection
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │    signatures/*.csv           │
                    │    (hash signatures)          │
                    └───────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                      STAGE 4: DEDUPLICATION                             │
│                   scripts/clean_duplicates.py                           │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                Remove duplicates within and across datasets
                based on content signatures
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │ clean/standardized/*.csv      │
                    │ clean/signatures/*.csv        │
                    │ (deduplicated data)           │
                    └───────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                    STAGE 5: BENCHMARK CREATION                          │
│                   scripts/create_benchmark.py                           │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                Merge all datasets into unified JSON format
                Organize by language and CWE
                                    │
                                    ▼
                    ┌───────────────────────────────┐
                    │      benchmark.json           │
                    │  { language: { cwe: [...] }}  │
                    └───────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                  STAGE 6: FILTERING & SAMPLING                          │
│      scripts/filter_benchmark.py & scripts/cluster_benchmark.py         │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                    ┌───────────────┼───────────────┐
                    │               │               │
         ┌──────────▼───────┐  ┌───▼──────────────────┐
         │  Stratified      │  │  Embedding-based     │
         │  Sampling        │  │  Clustering          │
         └──────────┬───────┘  └───┬──────────────────┘
                    │               │
                    └───────┬───────┘
                            ▼
            ┌───────────────────────────────┐
            │ benchmark_filtered.json       │
            │ benchmark_cluster.jsonl       │
            │ (representative samples)      │
            └───────────────────────────────┘

┌─────────────────────────────────────────────────────────────────────────┐
│                    STAGE 7: ANALYSIS & REPORTING                        │
│     scripts/analyze_cwe.py, scripts/cwe_stats.py, etc.                 │
└─────────────────────────────────────────────────────────────────────────┘
                                    │
                                    ▼
            ┌───────────────────────────────┐
            │ • cwe_counts.json             │
            │ • category_summary.csv        │
            │ • statistics reports          │
            └───────────────────────────────┘
```

## Detailed Stage Descriptions

### Stage 1: Raw Datasets

**Input:** Raw vulnerability datasets from various sources

**Datasets:**
- **CrossVul**: Cross-platform vulnerability dataset
- **CVEfixes**: CVE fixes from GitHub
- **MegaVul**: Large-scale vulnerability dataset
- **JaConTeBe**: Java context-aware benchmarks
- **Juliet**: NIST Juliet Test Suite
- **MSR**: Mining Software Repositories dataset
- **PrimeVul**: Primary vulnerability dataset
- **SVEN**: Secure VulNerability dataset

**Location:** `crossvul/`, `cvfixes/`, `megavul/`, etc.

### Stage 2: Standardization

**Script:** `scripts/normalize_datasets.py`

**Purpose:** Convert all datasets to a unified format with consistent schema

**Standardized Schema:**
```
- cwe:         CWE identifier (e.g., "CWE-79")
- code_before: Vulnerable code snippet
- code_after:  Fixed code snippet
- commit_url:  Source commit URL
- language:    Programming language
```

**Output:** `standardized/*.csv` (one file per dataset)

**Example:**
```bash
python scripts/normalize_datasets.py
```

### Stage 3: Signature Generation

**Script:** `scripts/signatures.py`

**Purpose:** Generate content-based signatures for duplicate detection

**Process:**
1. Read standardized CSV files
2. Compute hash signatures based on code content
3. Save signatures for deduplication

**Output:** `signatures/*.csv`

**Example:**
```bash
python scripts/signatures.py
```

### Stage 4: Deduplication

**Script:** `scripts/clean_duplicates.py`

**Purpose:** Remove duplicate entries within and across datasets

**Process:**
1. Load signature manifests
2. Identify duplicates based on content hashes
3. Remove duplicates, keeping first occurrence
4. Save cleaned data

**Output:**
- `clean/standardized/*.csv`: Deduplicated standardized data
- `clean/signatures/*.csv`: Updated signatures

**Example:**
```bash
python scripts/clean_duplicates.py
```

### Stage 5: Benchmark Creation

**Script:** `scripts/create_benchmark.py`

**Purpose:** Merge all cleaned datasets into a unified benchmark

**Process:**
1. Read all cleaned CSV files
2. Parse and validate entries
3. Organize by language and CWE
4. Output unified JSON structure

**Output Format:**
```json
{
  "Python": {
    "CWE-79": [
      {
        "code_before": "...",
        "code_after": "...",
        "commit_url": "...",
        "cwe": "CWE-79",
        "language": "Python"
      }
    ]
  }
}
```

**Output:** `benchmark.json`

**Example:**
```bash
python scripts/create_benchmark.py
```

### Stage 6: Filtering & Sampling

#### Option A: Stratified Sampling

**Script:** `scripts/filter_benchmark.py`

**Purpose:** Select diverse representative samples per CWE

**Strategy:**
- Stratified sampling based on code complexity
- Default: 10 samples per CWE per language
- Preserves diversity in code length and structure

**Output:** `benchmark_filtered.json`

**Example:**
```bash
python scripts/filter_benchmark.py
```

#### Option B: Embedding-based Clustering

**Script:** `scripts/cluster_benchmark.py`

**Purpose:** Use ML embeddings to cluster and select representative samples

**Features:**
- OpenAI embeddings for code similarity
- K-means clustering for large CWE groups
- Caching for efficiency
- Memory-optimized for large datasets

**Output:** `benchmark_cluster.jsonl`

**Requirements:**
```bash
pip install openai scikit-learn numpy ijson
```

**Example:**
```bash
# Set OpenAI API key in .env
echo "OPENAI_API_KEY=your_key" > .env

python scripts/cluster_benchmark.py
```

### Stage 7: Analysis & Reporting

#### CWE Analysis

**Script:** `scripts/analyze_cwe.py`

**Purpose:** Analyze CWE distribution and statistics

**Features:**
- Simple CWE counting
- Detailed single vs multi-CWE analysis
- CSV export for further analysis

**Examples:**
```bash
# Simple counting
python scripts/analyze_cwe.py benchmark_filtered.jsonl

# Detailed analysis
python scripts/analyze_cwe.py benchmark_filtered.jsonl --detailed

# Save to CSV
python scripts/analyze_cwe.py benchmark_filtered.jsonl --detailed -o stats.csv
```

#### Other Analysis Tools

- **scripts/cwe_stats.py**: Comprehensive CWE statistics
- **scripts/category_summary.py**: Category-level summaries
- **scripts/analyze_cwe_stats.py**: Advanced CWE analytics

## Data Format Specifications

### CSV Format (Standardized)

```csv
cwe,code_before,code_after,commit_url,language
CWE-79,"vulnerable code","fixed code",https://github.com/...,Python
```

### JSON Format (Benchmark)

```json
{
  "language": {
    "CWE-XXX": [
      {
        "code_before": "string",
        "code_after": "string",
        "commit_url": "string",
        "cwe": "CWE-XXX",
        "language": "string",
        "benign_lines": [...],
        "vuln_lines": [...],
        "other_cwes": [...]
      }
    ]
  }
}
```

### JSONL Format (Filtered/Clustered)

```jsonl
{"language": "Python", "cwe": "CWE-79", "code_before": "...", ...}
{"language": "Java", "cwe": "CWE-89", "code_before": "...", ...}
```

## Common Workflows

### Complete Pipeline Run

```bash
# 1. Standardize all datasets
python scripts/normalize_datasets.py

# 2. Generate signatures
python scripts/signatures.py

# 3. Remove duplicates
python scripts/clean_duplicates.py

# 4. Create unified benchmark
python scripts/create_benchmark.py

# 5. Filter to representative samples
python scripts/filter_benchmark.py

# 6. Analyze results
python scripts/analyze_cwe.py benchmark_filtered.jsonl --detailed
```

### Quick Analysis of Existing Benchmark

```bash
# Analyze CWE distribution
python scripts/analyze_cwe.py benchmark.json

# Get detailed statistics
python scripts/cwe_stats.py benchmark.json

# Create category summary
python scripts/category_summary.py
```

### Incremental Updates

```bash
# Add new dataset
# 1. Place in appropriate directory (e.g., new_dataset/)
# 2. Update normalize_datasets.py with new dataset handler
# 3. Run pipeline from stage 2 onwards
python scripts/normalize_datasets.py
python scripts/create_benchmark.py
```

## Utility Modules

The pipeline uses shared utility modules located in `src/utils/`:

- **json_utils.py**: JSON/JSONL file operations
- **file_utils.py**: File I/O with error handling
- **cwe_utils.py**: CWE normalization and analysis
- **benchmark_utils.py**: Benchmark data processing
- **logging_utils.py**: Consistent logging setup
- **cli_utils.py**: Command-line argument parsing

## Performance Considerations

### Memory Management

- Use streaming for large files (JSONL format)
- Process datasets incrementally
- Clear memory between processing stages

### Processing Time

- **Standardization**: 1-5 minutes per dataset
- **Deduplication**: 5-15 minutes (depends on dataset size)
- **Benchmark creation**: 2-10 minutes
- **Filtering**: 1-5 minutes
- **Clustering**: 30-120 minutes (with embeddings)

### Disk Space

- Raw datasets: ~500MB - 2GB
- Standardized: ~300MB - 1GB
- Clean: ~200MB - 800MB
- Benchmark: ~100MB - 500MB
- Filtered: ~10MB - 100MB

## Troubleshooting

### Common Issues

**Memory errors during processing:**
- Use JSONL format for large files
- Process datasets one at a time
- Increase system swap space

**Duplicate detection false positives:**
- Review signature generation logic
- Adjust similarity thresholds
- Manual review of edge cases

**Missing CWE identifiers:**
- Check source dataset quality
- Review normalization rules
- Use "Unknown" for unidentified CWEs

## References

- [CWE Database](https://cwe.mitre.org/)
- [Dataset Sources](../README.md#data-sources)
- [Contributing Guidelines](../CONTRIBUTING.md)
