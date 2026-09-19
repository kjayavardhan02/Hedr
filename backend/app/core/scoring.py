"""Deterministic weight/severity table and grade calculation.

Weights roughly follow the example in spec section 14. Any header not in
this table falls back to DEFAULT_WEIGHT / DEFAULT_SEVERITY so custom
policies with arbitrary headers still score sensibly.
"""
from __future__ import annotations

WEIGHT_TABLE: dict[str, float] = {
    "strict-transport-security": 20,
    "content-security-policy": 40,
    "x-content-type-options": 10,
    "referrer-policy": 10,
    "permissions-policy": 10,
    "cross-origin-opener-policy": 5,
    "cross-origin-resource-policy": 5,
    "cross-origin-embedder-policy": 5,
    "x-frame-options": 10,
    "x-xss-protection": 5,
    "cache-control": 10,
    "access-control-allow-origin": 10,
    "access-control-allow-credentials": 5,
}

SEVERITY_TABLE: dict[str, str] = {
    "strict-transport-security": "high",
    "content-security-policy": "critical",
    "x-content-type-options": "medium",
    "referrer-policy": "low",
    "permissions-policy": "low",
    "cross-origin-opener-policy": "low",
    "cross-origin-resource-policy": "low",
    "cross-origin-embedder-policy": "low",
    "x-frame-options": "medium",
    "x-xss-protection": "info",
    "cache-control": "medium",
    "access-control-allow-origin": "medium",
    "access-control-allow-credentials": "medium",
}

DEFAULT_WEIGHT = 5.0
DEFAULT_SEVERITY = "medium"


def get_weight(header_name: str) -> float:
    return WEIGHT_TABLE.get(header_name.lower(), DEFAULT_WEIGHT)


def get_severity(header_name: str) -> str:
    return SEVERITY_TABLE.get(header_name.lower(), DEFAULT_SEVERITY)


def grade_for_score(score: float) -> str:
    if score >= 90:
        return "A"
    if score >= 80:
        return "B"
    if score >= 70:
        return "C"
    if score >= 60:
        return "D"
    return "F"
