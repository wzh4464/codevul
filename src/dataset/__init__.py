"""Dataset normalization entrypoints."""

from . import crossvul, jacontebe, megavul, msr, primevul, sven
from .common import SCHEMA

NORMALIZERS = {
    crossvul.DATASET_NAME: crossvul.normalize,
    jacontebe.DATASET_NAME: jacontebe.normalize,
    msr.DATASET_NAME: msr.normalize,
    primevul.DATASET_NAME: primevul.normalize,
    megavul.DATASET_NAME: megavul.normalize,
    sven.DATASET_NAME: sven.normalize,
}

__all__ = ["NORMALIZERS", "SCHEMA"]
