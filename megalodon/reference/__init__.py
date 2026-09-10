"""Pinned public context data and synthetic evaluation resources.

The package has no downloader or update path.  Registry records are hints for
analyst interpretation, never observed services or security verdicts.
"""

from .loader import (
    CorpusBundle,
    CorpusScenario,
    IanaBundle,
    ProtocolNumberRecord,
    ReferenceDataError,
    ServicePortRecord,
    evaluate_corpus,
    load_corpus,
    load_iana,
    lookup_port,
    lookup_protocol,
)

__all__ = (
    "CorpusBundle",
    "CorpusScenario",
    "IanaBundle",
    "ProtocolNumberRecord",
    "ReferenceDataError",
    "ServicePortRecord",
    "evaluate_corpus",
    "load_corpus",
    "load_iana",
    "lookup_port",
    "lookup_protocol",
)
