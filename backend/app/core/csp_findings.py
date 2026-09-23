"""Centralized, stable CSP finding identifiers and their severities.

IDs are assigned here once and referenced by name everywhere else - never
generated from a check's description text, so they stay stable even if
wording changes later. Each ID also has exactly one severity, independent
of `scoring.SEVERITY_TABLE` (which is keyed per *header*, one severity for
the whole Content-Security-Policy header) - these are keyed per *finding
type within* CSP, a finer granularity that table was never meant to hold.
"""
from __future__ import annotations


class CSPFindingId:
    HEADER_MISSING = "CSP-000"
    REQUIRED_DIRECTIVE_MISSING = "CSP-001"
    PROHIBITED_SOURCE_PRESENT = "CSP-002"
    WILDCARD_SOURCE = "CSP-003"
    UNSAFE_INLINE = "CSP-004"
    UNSAFE_EVAL = "CSP-005"
    UNAPPROVED_SOURCE = "CSP-006"
    DATA_SCHEME_DETECTED = "CSP-007"
    BLOB_SCHEME_DETECTED = "CSP-008"
    MUST_CONTAIN_MISSING = "CSP-009"
    OBJECT_SRC_NOT_NONE = "CSP-010"
    BASE_URI_MISSING = "CSP-011"
    FRAME_ANCESTORS_MISSING = "CSP-012"
    EXTERNAL_SOURCE_DISALLOWED = "CSP-013"
    HTTP_SOURCE_DISALLOWED = "CSP-014"


CSP_FINDING_SEVERITY: dict[str, str] = {
    CSPFindingId.HEADER_MISSING: "critical",
    CSPFindingId.REQUIRED_DIRECTIVE_MISSING: "high",
    CSPFindingId.PROHIBITED_SOURCE_PRESENT: "high",
    CSPFindingId.WILDCARD_SOURCE: "medium",
    CSPFindingId.UNSAFE_INLINE: "high",
    CSPFindingId.UNSAFE_EVAL: "high",
    CSPFindingId.UNAPPROVED_SOURCE: "medium",
    CSPFindingId.DATA_SCHEME_DETECTED: "low",
    CSPFindingId.BLOB_SCHEME_DETECTED: "low",
    CSPFindingId.MUST_CONTAIN_MISSING: "high",
    CSPFindingId.OBJECT_SRC_NOT_NONE: "medium",
    CSPFindingId.BASE_URI_MISSING: "low",
    CSPFindingId.FRAME_ANCESTORS_MISSING: "medium",
    CSPFindingId.EXTERNAL_SOURCE_DISALLOWED: "medium",
    CSPFindingId.HTTP_SOURCE_DISALLOWED: "medium",
}


def severity_for(finding_id: str) -> str:
    return CSP_FINDING_SEVERITY.get(finding_id, "medium")
