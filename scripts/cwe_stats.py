#!/usr/bin/env python3
"""Compute per-dataset CWE sample counts limited to the CWE IDs in collect.json."""

from __future__ import annotations

import csv
import json
import re
import sys
from collections import Counter
import gzip
from pathlib import Path
from typing import Iterable, Iterator

import pyarrow.ipc as pa_ipc


ROOT = Path(__file__).resolve().parents[1]
CWE_PATTERN = re.compile(r"CWE-(\d+)")
csv.field_size_limit(sys.maxsize)


def normalize_cwe(value: object) -> str | None:
    """Normalise a raw CWE reference to 'CWE-<number>'."""
    if value is None:
        return None
    if isinstance(value, int):
        return f"CWE-{value}"

    text = str(value).strip()
    if not text:
        return None
    upper = text.upper()
    if not text:
        return None

    match = CWE_PATTERN.search(upper)
    if match:
        return f"CWE-{int(match.group(1))}"

    if upper.isdigit():
        return f"CWE-{int(text)}"

    return None


def extract_cwes(raw: object) -> set[str]:
    """Extract CWE identifiers from arbitrary raw structures."""
    result: set[str] = set()
    if raw is None:
        return result

    if isinstance(raw, (list, tuple, set)):
        for item in raw:
            result.update(extract_cwes(item))
        return result

    if isinstance(raw, str):
        for match in CWE_PATTERN.findall(raw.upper()):
            result.add(f"CWE-{int(match)}")
        if result:
            return result

    normalized = normalize_cwe(raw)
    if normalized:
        result.add(normalized)

    return result


def iter_json_array(path: Path, chunk_size: int = 1_048_576) -> Iterator[dict]:
    """Stream JSON objects from a large array without loading the whole file."""
    decoder = json.JSONDecoder()
    buffer = ""
    in_array = False

    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        while True:
            chunk = fh.read(chunk_size)
            if not chunk:
                break
            buffer += chunk

            while True:
                buffer = buffer.lstrip()
                if not buffer:
                    break

                if not in_array:
                    if buffer.startswith("["):
                        in_array = True
                        buffer = buffer[1:]
                        continue
                    raise ValueError(f"{path} must start with a JSON array.")

                if buffer.startswith("]"):
                    return

                try:
                    obj, offset = decoder.raw_decode(buffer)
                except json.JSONDecodeError:
                    # Need more data, read the next chunk.
                    break

                yield obj
                buffer = buffer[offset:].lstrip()
                if buffer.startswith(","):
                    buffer = buffer[1:]

        buffer = buffer.lstrip()
        if in_array and buffer.startswith("]"):
            return
        if buffer:
            raise ValueError(f"Unexpected trailing data in {path}: {buffer[:80]!r}")


def load_target_cwes(root: Path) -> set[str]:
    """Read collect.json and build the set of CWE identifiers to include."""
    collect_path = root / "collect.json"
    if not collect_path.exists():
        return set()

    with collect_path.open("r", encoding="utf-8") as fh:
        data = json.load(fh)

    targets: set[str] = set()

    def visit(node: object) -> None:
        if isinstance(node, dict):
            for value in node.values():
                visit(value)
        elif isinstance(node, (list, tuple, set)):
            for item in node:
                visit(item)
        else:
            targets.update(extract_cwes(node))

    visit(data)
    return targets


def filter_target(cwes: Iterable[str], targets: set[str]) -> set[str]:
    return {cwe for cwe in cwes if cwe in targets}


def count_crossvul(root: Path, targets: set[str]) -> Counter[str]:
    metadata_path = root / "crossvul" / "metadata.json"
    counter: Counter[str] = Counter()
    if not metadata_path.exists():
        return counter

    with metadata_path.open("r", encoding="utf-8") as fh:
        records = json.load(fh)

    for record in records:
        cwes = filter_target(extract_cwes(record.get("cwe")), targets)
        for cwe in cwes:
            counter[cwe] += 1

    return counter


def count_megavul(root: Path, targets: set[str]) -> Counter[str]:
    base = root / "megavul" / "megavul"
    counter: Counter[str] = Counter()
    if not base.exists():
        return counter

    for version_dir in sorted(base.iterdir()):
        dataset_path = version_dir / "c_cpp" / "cve_with_graph_abstract_commit.json"
        if not dataset_path.exists():
            continue

        for record in iter_json_array(dataset_path):
            cwes = filter_target(extract_cwes(record.get("cwe_ids")), targets)
            for cwe in cwes:
                counter[cwe] += 1

    return counter


def count_msr(root: Path, targets: set[str]) -> Counter[str]:
    csv_path = root / "MSR" / "MSR_data_cleaned.csv"
    counter: Counter[str] = Counter()
    if not csv_path.exists():
        return counter

    with csv_path.open("r", encoding="utf-8", errors="ignore", newline="") as fh:
        reader = csv.DictReader(fh)
        for row in reader:
            cwes = filter_target(extract_cwes(row.get("CWE ID")), targets)
            for cwe in cwes:
                counter[cwe] += 1

    return counter


def iter_jsonl(path: Path) -> Iterator[dict]:
    """Yield JSON objects from a JSONL file."""
    with path.open("r", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            try:
                yield json.loads(line)
            except json.JSONDecodeError:
                continue


def count_primevul(root: Path, targets: set[str]) -> Counter[str]:
    base = root / "primevul"
    counter: Counter[str] = Counter()
    if not base.exists():
        return counter

    for filename in (
        "primevul_train_paired.jsonl",
        "primevul_valid_paired.jsonl",
        "primevul_test_paired.jsonl",
    ):
        path = base / filename
        if not path.exists():
            continue
        for record in iter_jsonl(path):
            cwes = filter_target(extract_cwes(record.get("cwe")), targets)
            for cwe in cwes:
                counter[cwe] += 1

    return counter


def count_juliet(root: Path, targets: set[str]) -> Counter[str]:
    base = root / "juliet"
    counter: Counter[str] = Counter()
    if not base.exists():
        return counter

    arrow_paths = [
        base / "juliet_test_suite_c_1_3-train.arrow",
        base / "juliet_test_suite_c_1_3-test.arrow",
    ]

    for path in arrow_paths:
        if not path.exists():
            continue
        with path.open("rb") as fh:
            reader = pa_ipc.open_stream(fh)
            filename_index = reader.schema.get_field_index("filename")
            for batch in reader:
                column = batch.column(filename_index)
                for value in column:
                    filename = value.as_py()
                    cwes = filter_target(extract_cwes(filename), targets)
                    for cwe in cwes:
                        counter[cwe] += 1

    return counter


def count_sven(root: Path, targets: set[str]) -> Counter[str]:
    base = root / "sven" / "data_train_val"
    counter: Counter[str] = Counter()
    if not base.exists():
        return counter

    for split in ("train", "val"):
        split_dir = base / split
        if not split_dir.exists():
            continue
        for jsonl_path in sorted(split_dir.glob("cwe-*.jsonl")):
            for record in iter_jsonl(jsonl_path):
                cwes = filter_target(extract_cwes(record.get("vul_type")), targets)
                for cwe in cwes:
                    counter[cwe] += 1

    return counter


def count_cvefixes(root: Path, targets: set[str]) -> Counter[str]:
    """Count CVE→CWE mappings by scanning the CVEfixes SQL dump.

    CVEfixes 1.0.8 is distributed as `Data/CVEfixes_vX.Y.Z.sql.gz`. The dump
    contains single-row INSERT statements for the `cwe_classification` table,
    which records the CWE identifier assigned to each CVE. We stream the gzipped
    SQL file line-by-line, pick out those INSERTs, normalise their CWE payload,
    and tally the rows that match our target CWE set.
    """
    sql_path = _locate_latest_cvefixes_sql(root)
    counter: Counter[str] = Counter()
    if not sql_path.exists():
        return counter

    insert_prefix = "INSERT INTO cwe_classification"
    pattern = re.compile(
        r"INSERT INTO cwe_classification VALUES\('([^']+)','([^']+)'\);"
    )

    with gzip.open(sql_path, "rt", encoding="utf-8", errors="ignore") as fh:
        for line in fh:
            if insert_prefix not in line:
                continue
            match = pattern.search(line)
            if not match:
                continue
            _, raw_cwe = match.groups()
            cwes = filter_target(extract_cwes(raw_cwe), targets)
            for cwe in cwes:
                counter[cwe] += 1

    return counter


def _locate_latest_cvefixes_sql(root: Path) -> Path:
    """Find the newest CVEfixes SQL dump available under /cvfixes."""
    base = root / "cvfixes"
    version_pattern = re.compile(r"CVEfixes_v(\d+(?:\.\d+)*)")
    default_path = base / "CVEfixes_v1.0.8" / "Data" / "CVEfixes_v1.0.8.sql.gz"
    best_path = default_path
    best_version: tuple[int, ...] | None = None
    if default_path.exists():
        best_version = tuple(int(part) for part in "1.0.8".split("."))

    if base.exists():
        for entry in base.iterdir():
            if not entry.is_dir():
                continue
            match = version_pattern.fullmatch(entry.name)
            if not match:
                continue
            version_tuple = tuple(int(part) for part in match.group(1).split("."))
            data_dir = entry / "Data"
            sql_path = data_dir / f"{entry.name}.sql.gz"
            if not sql_path.exists():
                continue
            if best_version is None or version_tuple > best_version:
                best_version = version_tuple
                best_path = sql_path

    return best_path


def main() -> None:
    target_cwes = load_target_cwes(ROOT)
    if not target_cwes:
        print("No target CWE IDs found in collect.json; nothing to do.")
        return

    dataset_counters = {
        "crossvul": count_crossvul(ROOT, target_cwes),
        "megavul": count_megavul(ROOT, target_cwes),
        "MSR": count_msr(ROOT, target_cwes),
        "primevul": count_primevul(ROOT, target_cwes),
        "cvfixes": count_cvefixes(ROOT, target_cwes),
        "juliet": count_juliet(ROOT, target_cwes),
        "sven": count_sven(ROOT, target_cwes),
        "devign": Counter(),
        "ReVeal": Counter(),
    }

    output_path = ROOT / "cwe_counts.json"
    dataset_details = {}
    totals = {}
    for name, counter in dataset_counters.items():
        total = sum(counter.values())
        totals[name] = total
        dataset_details[name] = {
            "total": total,
            "per_cwe": {cwe: counter.get(cwe, 0) for cwe in sorted(target_cwes)},
        }

    payload = {
        "target_cwes": sorted(target_cwes),
        "totals": totals,
        "datasets": dataset_details,
    }
    output_path.write_text(
        json.dumps(payload, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )

    print("Target CWE IDs:", ", ".join(sorted(target_cwes)))
    for name, counter in dataset_counters.items():
        total = sum(counter.values())
        print(f"[{name}] matching samples: {total}")
        for cwe in sorted(target_cwes):
            print(f"  {cwe}: {counter.get(cwe, 0)}")

    print("\nDataset totals:")
    for name, total in totals.items():
        print(f"  {name}: {total}")

    print(f"\nDetailed JSON output saved to {output_path.name}")


if __name__ == "__main__":
    main()
