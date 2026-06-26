"""Package exceptions."""


class ProblemFrameGateError(Exception):
    """Base class for package-specific errors."""


class SecurityError(ProblemFrameGateError):
    """Raised when a payload contains data that should not enter an audit log."""


class LogVerificationError(ProblemFrameGateError):
    """Raised when an envelope log is not legal for a horizon."""


class FoldError(ProblemFrameGateError):
    """Raised when a deterministic component replay rejects an envelope."""
