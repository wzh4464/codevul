"""Normalization logic for the megavul dataset."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Iterator, List, Optional, Tuple

from .common import ensure_https, iter_json_array, normalize_cwe, write_rows

logger = logging.getLogger(__name__)

DATASET_NAME = "megavul"


def _build_commit_url(commit: dict) -> str:
    url = ensure_https(commit.get("git_url"))
    if url:
        return url

    repo = commit.get("repo_name") or ""
    commit_hash = commit.get("commit_hash") or ""
    if not repo or not commit_hash:
        return ""
    repo = repo.strip("/")
    if repo.startswith(("http://", "https://")):
        base = ensure_https(repo)
    else:
        base = f"https://github.com/{repo}"
    return f"{base}/commit/{commit_hash}"


def normalize(
    root: Path,
    outdir: Path,
    *,
    limit: Optional[int] = None,
) -> Optional[Tuple[Path, int, bool]]:
    base = root / "megavul" / "megavul"
    if not base.exists():
        logger.warning("Missing megavul directory: %s", base)
        return None

    dataset_paths = sorted(
        (path / "c_cpp" / "cve_with_graph_abstract_commit.json")
        for path in base.iterdir()
        if path.is_dir()
    )
    dataset_paths = [path for path in dataset_paths if path.exists()]
    if not dataset_paths:
        logger.warning("No megavul JSON dumps located under %s", base)
        return None

    def generate() -> Iterator[List[str]]:
        for dataset_path in dataset_paths:
            logger.info("Reading megavul dataset %s", dataset_path)
            for entry in iter_json_array(dataset_path):
                cwes = entry.get("cwe_ids") or []
                normalized_cwes = [
                    normalize_cwe(cwe_value) for cwe_value in cwes if cwe_value
                ]
                cwe_field = "|".join(filter(None, normalized_cwes))
                for commit in entry.get("commits", []):
                    commit_url = _build_commit_url(commit)
                    for file_info in commit.get("files", []):
                        language = file_info.get("language") or ""
                        for func in file_info.get("vulnerable_functions", []):
                            code_before = func.get("func_before")
                            code_after = func.get("func_after")
                            if not code_before or not code_after:
                                continue
                            yield [
                                cwe_field,
                                code_before,
                                code_after,
                                commit_url,
                                language,
                            ]

    output_path = outdir / f"{DATASET_NAME}.csv"
    rows_written, truncated = write_rows(
        output_path, generate(), limit=limit
    )
    if rows_written == 0:
        logger.warning("megavul produced no rows for %s", output_path)
    else:
        info_extra = " (truncated)" if truncated else ""
        logger.info(
            "megavul: wrote %d rows to %s%s",
            rows_written,
            output_path,
            info_extra,
        )
    return output_path, rows_written, truncated
