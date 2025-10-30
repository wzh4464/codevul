"""Unified CLI for dataset normalization, CWE matching, and summary reports."""

from __future__ import annotations

import argparse
import logging
from pathlib import Path
from typing import Dict, Iterable, List, Optional

from scripts.category_summary import generate_category_summary
from scripts.cwe_stats import DATASET_COUNTERS, generate_cwe_stats
from scripts.signatures import generate_signatures
from src.dataset import NORMALIZERS

ROOT = Path(__file__).resolve().parent


def _canonical_dataset(value: str) -> str:
    return value.strip().lower().rstrip("/")


def _build_pipeline_config() -> Dict[str, Dict[str, str]]:
    config: Dict[str, Dict[str, str]] = {}
    for name in NORMALIZERS:
        canonical = _canonical_dataset(name)
        config.setdefault(canonical, {})["normalizer"] = name
        config[canonical]["signature"] = name
    for name in DATASET_COUNTERS:
        canonical = _canonical_dataset(name)
        config.setdefault(canonical, {})["cwe"] = name
    return config


PIPELINE_CONFIG = _build_pipeline_config()
PIPELINE_ORDER = list(
    dict.fromkeys(
        [_canonical_dataset(name) for name in DATASET_COUNTERS]
        + list(PIPELINE_CONFIG)
    )
)


def _resolve_selected_datasets(
    requested: Optional[Iterable[str]],
) -> List[str]:
    if not requested:
        return PIPELINE_ORDER

    tokens: List[str] = []
    for raw in requested:
        canonical = _canonical_dataset(raw or "")
        if not canonical:
            continue
        if canonical == "all":
            return PIPELINE_ORDER
        if canonical not in PIPELINE_CONFIG:
            available = ", ".join(sorted(PIPELINE_CONFIG))
            raise ValueError(
                f"Unknown dataset '{raw}'. Available datasets: {available}"
            )
        tokens.append(canonical)

    if not tokens:
        return PIPELINE_ORDER

    ordered: List[str] = []
    seen = set()
    for name in PIPELINE_ORDER:
        if name in tokens and name not in seen:
            ordered.append(name)
            seen.add(name)
    for name in tokens:
        if name not in seen:
            ordered.append(name)
            seen.add(name)

    return ordered


def _parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=__doc__,
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--dataset",
        dest="datasets",
        action="append",
        help="Dataset to process (repeat for multiple). Use 'all' for every dataset.",
        metavar="NAME",
    )
    parser.add_argument(
        "--root",
        default=".",
        help="Repository root.",
        metavar="PATH",
    )
    parser.add_argument(
        "--output-dir",
        default="standardized",
        help="Destination directory for normalized CSVs.",
        metavar="DIR",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Stop normalization after writing N rows per dataset.",
        metavar="N",
    )
    parser.add_argument(
        "--verbose",
        action="store_true",
        help="Enable verbose logging.",
    )
    parser.add_argument(
        "--force-normalize",
        action="store_true",
        help="Always run normalization even if the target CSV already exists.",
    )
    parser.add_argument(
        "--signature-dir",
        default="signatures",
        help="Directory for generated signature CSVs.",
        metavar="DIR",
    )
    parser.add_argument(
        "--force-signatures",
        action="store_true",
        help="Rebuild signature files even if they already exist.",
    )
    return parser.parse_args()


def _run_normalization(
    dataset_keys: Iterable[str],
    root: Path,
    output_dir: Path,
    limit: Optional[int],
    force: bool,
) -> None:
    for key in dataset_keys:
        normalizer_name = PIPELINE_CONFIG[key].get("normalizer")
        if not normalizer_name:
            logging.info(
                "Skipping normalization for dataset %s (no normalizer).",
                key,
            )
            continue
        normalizer = NORMALIZERS[normalizer_name]
        target_path = output_dir / f"{normalizer_name}.csv"
        if not force and target_path.exists():
            logging.info(
                "Skipping normalization for dataset %s (found %s).",
                normalizer_name,
                target_path,
            )
            continue
        logging.info("Normalizing dataset %s", normalizer_name)
        result = normalizer(root, output_dir, limit=limit)
        if result is None:
            logging.warning("Dataset %s skipped due to missing inputs.", normalizer_name)
            continue
        output_path, rows_written, truncated = result
        if truncated:
            logging.info(
                "Wrote %d rows to %s (truncated at limit %s).",
                rows_written,
                output_path,
                limit,
            )
        else:
            logging.info("Wrote %d rows to %s.", rows_written, output_path)


def _run_signatures(
    dataset_keys: Iterable[str],
    root: Path,
    signature_dir: Path,
    force: bool,
) -> None:
    signature_datasets = [
        PIPELINE_CONFIG[key]["signature"]
        for key in dataset_keys
        if "signature" in PIPELINE_CONFIG[key]
    ]
    if not signature_datasets:
        logging.info("No datasets selected for signature generation; skipping.")
        return

    logging.info(
        "Generating signatures for: %s",
        ", ".join(signature_datasets),
    )
    generate_signatures(
        datasets=signature_datasets,
        root=root,
        output_dir=signature_dir,
        force=force,
    )


def _run_cwe_stats(dataset_keys: Iterable[str]) -> Optional[dict]:
    cwe_datasets = [
        PIPELINE_CONFIG[key]["cwe"]
        for key in dataset_keys
        if "cwe" in PIPELINE_CONFIG[key]
    ]
    if not cwe_datasets:
        logging.info("No datasets selected for CWE statistics; skipping.")
        return None

    logging.info(
        "Computing CWE statistics for: %s",
        ", ".join(cwe_datasets),
    )
    return generate_cwe_stats(cwe_datasets)


def _run_category_summary(dataset_keys: Iterable[str]) -> None:
    cwe_datasets = [
        PIPELINE_CONFIG[key]["cwe"]
        for key in dataset_keys
        if "cwe" in PIPELINE_CONFIG[key]
    ]
    if not cwe_datasets:
        logging.info("No datasets selected for category summary; skipping.")
        return

    logging.info("Building category summaries.")
    generate_category_summary(cwe_datasets)


def main() -> None:
    args = _parse_args()
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(levelname)s: %(message)s",
    )

    try:
        dataset_keys = _resolve_selected_datasets(args.datasets)
    except ValueError as exc:
        raise SystemExit(str(exc)) from exc

    root = Path(args.root).resolve()
    output_dir = Path(args.output_dir)
    if not output_dir.is_absolute():
        output_dir = (root / output_dir).resolve()
    signature_dir = Path(args.signature_dir)
    if not signature_dir.is_absolute():
        signature_dir = (root / signature_dir).resolve()

    logging.info(
        "Pipeline start for datasets: %s",
        ", ".join(dataset_keys),
    )
    logging.debug("Repository root: %s", root)
    logging.debug("Output directory: %s", output_dir)
    logging.debug("Signature directory: %s", signature_dir)

    _run_normalization(dataset_keys, root, output_dir, args.limit, args.force_normalize)
    _run_signatures(dataset_keys, root, signature_dir, args.force_signatures)
    stats_payload = _run_cwe_stats(dataset_keys)
    if stats_payload is not None:
        _run_category_summary(dataset_keys)
    else:
        logging.info("Skipped summary generation because CWE stats were unavailable.")

    logging.info("Pipeline complete.")


if __name__ == "__main__":
    main()
