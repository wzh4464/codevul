"""Dataset normalization entrypoints."""

from . import cvefixes, jacontebe, juliet, megavul, msr, primevul, sven
from .common import SCHEMA

NORMALIZERS = {
    cvefixes.DATASET_NAME: cvefixes.normalize,
    jacontebe.DATASET_NAME: jacontebe.normalize,
    juliet.DATASET_NAME: juliet.normalize,
    msr.DATASET_NAME: msr.normalize,
    primevul.DATASET_NAME: primevul.normalize,
    megavul.DATASET_NAME: megavul.normalize,
    sven.DATASET_NAME: sven.normalize,
}

__all__ = ["NORMALIZERS", "SCHEMA"]
