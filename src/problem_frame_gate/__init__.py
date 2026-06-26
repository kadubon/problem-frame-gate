"""Practical finite audit calculus for AI problem-frame activation."""

from ._version import __version__
from .certificates import CertificateFamily, all_certificates_live, check_certificate_live
from .digest import canonical_json_bytes, digest_json, digest_many
from .fold import FoldKernel, FoldState, default_components
from .formation import FormationProof, check_formation, check_well_audited
from .gate import ExecutorGate, GateBundle, GateRecord, GateRequest
from .join import JoinChecker, JoinProposal, union_join
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
from .patch import AffectedClauseSet, PatchChecker, PatchProposal, ReadFootprint, TouchMatrix, WriteClass
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
    check_risk_claims,
    check_risk_ledger,
    check_risk_spend_live,
    summarize_risk_ledger,
)
from .security import SensitiveDataIssue, scan_for_sensitive_data
from .verifier import EnvelopeVerifier, canonical_order, digest_log, legal_log

__all__ = [
    "AffectedClauseSet",
    "AuditTranscript",
    "CertificateFamily",
    "CheckResult",
    "DependencyRef",
    "Envelope",
    "EnvelopeClass",
    "EnvelopeVerifier",
    "ExecutorGate",
    "FoldKernel",
    "FoldState",
    "FormationProof",
    "Frame",
    "GateBundle",
    "GateRecord",
    "GateRequest",
    "Horizon",
    "Issue",
    "JoinChecker",
    "JoinProposal",
    "OrderEdge",
    "PatchChecker",
    "PatchProposal",
    "ReachabilityTranscript",
    "ReadFootprint",
    "ReplayCertificate",
    "RiskClaimRecord",
    "RiskLedgerSummary",
    "SensitiveDataIssue",
    "SourceCut",
    "Status",
    "StrictManifest",
    "SwapCover",
    "TouchMatrix",
    "TransitionRecord",
    "VersionInterval",
    "WriteClass",
    "__version__",
    "all_certificates_live",
    "canonical_json_bytes",
    "canonical_order",
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
    "legal_log",
    "scan_for_sensitive_data",
    "summarize_risk_ledger",
    "union_join",
]
