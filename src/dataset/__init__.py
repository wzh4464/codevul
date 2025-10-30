"""Dataset normalization entrypoints."""

from . import cvfixes, crossvul, jacontebe, juliet, megavul, msr, primevul, sven
from .common import SCHEMA

NORMALIZERS = {
    crossvul.DATASET_NAME: crossvul.normalize,
    cvfixes.DATASET_NAME: cvfixes.normalize,
    jacontebe.DATASET_NAME: jacontebe.normalize,
    juliet.DATASET_NAME: juliet.normalize,
    msr.DATASET_NAME: msr.normalize,
    primevul.DATASET_NAME: primevul.normalize,
    megavul.DATASET_NAME: megavul.normalize,
    sven.DATASET_NAME: sven.normalize,
}

__all__ = ["NORMALIZERS", "SCHEMA"]
