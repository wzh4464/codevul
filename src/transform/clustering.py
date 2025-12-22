"""Clustering and sampling for large CWD groups."""

from __future__ import annotations

import logging
import random
from collections import defaultdict
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger(__name__)

try:
    import numpy as np
    NUMPY_AVAILABLE = True
except ImportError:
    NUMPY_AVAILABLE = False
    logger.warning("numpy not available, clustering will use fallback methods")

try:
    from sklearn.cluster import KMeans
    SKLEARN_AVAILABLE = True
except ImportError:
    SKLEARN_AVAILABLE = False
    logger.warning("scikit-learn not available, clustering will use fallback methods")


def load_embeddings_from_cache(cwe: str, cache_dir: Path) -> Optional['np.ndarray']:
    """Load cached embeddings for a CWE."""
    if not NUMPY_AVAILABLE:
        return None

    cache_file = cache_dir / f"{cwe.replace('/', '_')}.npy"

    if cache_file.exists():
        try:
            embeddings = np.load(cache_file, allow_pickle=False)
            logger.info(f"  Loaded embeddings from cache: {embeddings.shape}")
            return embeddings
        except Exception as e:
            logger.warning(f"  Failed to load embeddings: {e}")

    return None


def stratified_sample(
    entries: List[Dict[str, Any]],
    n_samples: int
) -> List[Dict[str, Any]]:
    """
    Perform stratified sampling by source dataset.

    Args:
        entries: List of entries to sample
        n_samples: Number of samples to select

    Returns:
        List of sampled entries
    """
    by_source = defaultdict(list)
    for i, entry in enumerate(entries):
        by_source[entry['source']].append(i)

    # Calculate samples per source proportionally
    selected_indices = []
    remaining = n_samples

    for source, indices in sorted(by_source.items()):
        proportion = len(indices) / len(entries)
        count = min(remaining, max(1, int(n_samples * proportion)))
        selected_indices.extend(random.sample(indices, min(count, len(indices))))
        remaining -= count

        if remaining <= 0:
            break

    return [entries[i] for i in selected_indices[:n_samples]]


def kmeans_cluster_sample(
    entries: List[Dict[str, Any]],
    embeddings: 'np.ndarray',
    n_samples: int
) -> List[Dict[str, Any]]:
    """
    Perform KMeans clustering and select representatives.

    Args:
        entries: List of entries
        embeddings: Embeddings array matching entries
        n_samples: Number of clusters/samples

    Returns:
        List of representative entries
    """
    if not NUMPY_AVAILABLE or not SKLEARN_AVAILABLE:
        raise RuntimeError("numpy and sklearn required for clustering")

    logger.info(f"  Clustering {len(entries)} entries into {n_samples} clusters...")

    kmeans = KMeans(n_clusters=n_samples, random_state=42, n_init=10)
    labels = kmeans.fit_predict(embeddings)

    # Select closest sample to each cluster center
    selected_entries = []
    for cluster_id in range(n_samples):
        cluster_indices = np.where(labels == cluster_id)[0]

        if len(cluster_indices) == 0:
            continue

        # Find closest point to cluster center
        cluster_embeddings = embeddings[cluster_indices]
        center = kmeans.cluster_centers_[cluster_id]
        distances = np.linalg.norm(cluster_embeddings - center, axis=1)
        closest_idx = cluster_indices[np.argmin(distances)]

        selected_entries.append(entries[closest_idx])

    logger.info(f"  Selected {len(selected_entries)} representative samples")
    return selected_entries


def cluster_and_sample(
    entries: List[Dict[str, Any]],
    n_samples: int,
    cwe: str,
    embeddings_cache_dir: Path,
    method: str = 'kmeans'
) -> List[Dict[str, Any]]:
    """
    Cluster entries and select n_samples representatives.

    Args:
        entries: List of entries to cluster
        n_samples: Number of samples to select
        cwe: CWE identifier (for loading embeddings)
        embeddings_cache_dir: Directory containing cached embeddings
        method: Clustering method ('kmeans' or 'stratified')

    Returns:
        List of selected entries
    """
    if len(entries) <= n_samples:
        return entries

    # Try KMeans with embeddings if available
    if method == 'kmeans' and NUMPY_AVAILABLE and SKLEARN_AVAILABLE:
        embeddings = load_embeddings_from_cache(cwe, embeddings_cache_dir)

        if embeddings is not None and len(embeddings) == len(entries):
            try:
                return kmeans_cluster_sample(entries, embeddings, n_samples)
            except Exception as e:
                logger.warning(f"  KMeans clustering failed: {e}, falling back to stratified")

    # Fallback to stratified sampling
    logger.info(f"  Using stratified sampling for {cwe}")
    return stratified_sample(entries, n_samples)


def random_sample(
    entries: List[Dict[str, Any]],
    n_samples: int
) -> List[Dict[str, Any]]:
    """
    Randomly sample entries.

    Args:
        entries: List of entries
        n_samples: Number of samples

    Returns:
        Random sample of entries
    """
    return random.sample(entries, min(n_samples, len(entries)))
