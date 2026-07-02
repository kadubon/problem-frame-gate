"""Practical finite audit calculus for AI problem-frame activation."""

from ._version import __version__
from .broker import ActionDispatcher, BrokerPollResult, DispatchResult, OutboxBroker
from .certificates import (
    CertificateFamily,
    all_certificates_live,
    certificate_dependency_digest,
    check_certificate_live,
)
from .clock import ClockWatermark, ClockWatermarkProvider, IntegerClockWatermarkProvider
from .digest import canonical_json_bytes, digest_json, digest_many, is_sha256_digest
from .fold import FoldKernel, FoldState, default_components
from .formation import FormationBuildResult, FormationProof, FormationProofBuilder, check_formation, check_well_audited
from .gate import ExecutorGate, GateBundle, GateRecord, GateRequest
from .join import JoinChecker, JoinKey, JoinProposal, RepairWitness, union_join
from .metrics import MemoryMetricsSink, MetricsSink
from .model import (
    AuditTranscript,
    DependencyRef,
    Envelope,
    EnvelopeClass,
    Frame,
    Horizon,
    OrderEdge,
    Status,
    StrictManifest,
    VersionInterval,
)
from .patch import AffectedClauseSet, PatchChecker, PatchProposal, ReadFootprint, TouchMatrix, WriteClass, WriteCover
from .profiles import PROFILE_NAMES, RuntimeProfile, example_profile, production_profile
from .reachability import ReachabilityChecker, TransitionWitness
from .records import (
    ReachabilityTranscript,
    ReplayCertificate,
    SourceCut,
    SwapCover,
    TransitionRecord,
    check_reachability,
    check_replay_certificate,
    check_source_cut,
)
from .result import CheckResult, Issue
from .risk import (
    RiskClaimRecord,
    RiskLedgerSummary,
    RiskMode,
    RiskRouteWitness,
    check_risk_claims,
    check_risk_ledger,
    check_risk_spend_live,
    standard_risk_registry,
    summarize_risk_ledger,
)
from .runtime import GateCommitResult, GateCommitter
from .security import SensitiveDataIssue, scan_for_sensitive_data
from .signatures import SignatureRegistry, SignatureVerifier
from .storage import AppendOnlyStore, AppendResult, MemoryAppendOnlyStore, SQLiteAppendOnlyStore, StoreSnapshot
from .verifier import EnvelopeVerifier, canonical_order, digest_log, legal_log

__all__ = [
    "PROFILE_NAMES",
    "ActionDispatcher",
    "AffectedClauseSet",
    "AppendOnlyStore",
    "AppendResult",
    "AuditTranscript",
    "BrokerPollResult",
    "CertificateFamily",
    "CheckResult",
    "ClockWatermark",
    "ClockWatermarkProvider",
    "DependencyRef",
    "DispatchResult",
    "Envelope",
    "EnvelopeClass",
    "EnvelopeVerifier",
    "ExecutorGate",
    "FoldKernel",
    "FoldState",
    "FormationBuildResult",
    "FormationProof",
    "FormationProofBuilder",
    "Frame",
    "GateBundle",
    "GateCommitResult",
    "GateCommitter",
    "GateRecord",
    "GateRequest",
    "Horizon",
    "IntegerClockWatermarkProvider",
    "Issue",
    "JoinChecker",
    "JoinKey",
    "JoinProposal",
    "MemoryAppendOnlyStore",
    "MemoryMetricsSink",
    "MetricsSink",
    "OrderEdge",
    "OutboxBroker",
    "PatchChecker",
    "PatchProposal",
    "ReachabilityChecker",
    "ReachabilityTranscript",
    "ReadFootprint",
    "RepairWitness",
    "ReplayCertificate",
    "RiskClaimRecord",
    "RiskLedgerSummary",
    "RiskMode",
    "RiskRouteWitness",
    "RuntimeProfile",
    "SQLiteAppendOnlyStore",
    "SensitiveDataIssue",
    "SignatureRegistry",
    "SignatureVerifier",
    "SourceCut",
    "Status",
    "StoreSnapshot",
    "StrictManifest",
    "SwapCover",
    "TouchMatrix",
    "TransitionRecord",
    "TransitionWitness",
    "VersionInterval",
    "WriteClass",
    "WriteCover",
    "__version__",
    "all_certificates_live",
    "canonical_json_bytes",
    "canonical_order",
    "certificate_dependency_digest",
    "check_certificate_live",
    "check_formation",
    "check_reachability",
    "check_replay_certificate",
    "check_risk_claims",
    "check_risk_ledger",
    "check_risk_spend_live",
    "check_source_cut",
    "check_well_audited",
    "default_components",
    "digest_json",
    "digest_log",
    "digest_many",
    "example_profile",
    "is_sha256_digest",
    "legal_log",
    "production_profile",
    "scan_for_sensitive_data",
    "standard_risk_registry",
    "summarize_risk_ledger",
    "union_join",
]
