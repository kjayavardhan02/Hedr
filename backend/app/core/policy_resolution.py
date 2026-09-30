"""Resolves a saved Policy by id into the shapes app.core.policy_engine.run_scan
needs. Shared by the URL/raw scan endpoint and Burp History analysis, so both
apply the exact same ownership check and unwrap the same way."""
from __future__ import annotations

from dataclasses import dataclass

from sqlalchemy.orm import Session

from app import models
from app.schemas import CSPPolicy, PolicyHeaderIn


class PolicyNotFoundError(Exception):
    pass


@dataclass
class ResolvedPolicy:
    policy: models.Policy
    policy_headers: list[PolicyHeaderIn]
    policy_name: str
    policy_version: str
    csp_policy: CSPPolicy | None


def resolve_policy_by_id(db: Session, policy_id: str, current_user: models.User) -> ResolvedPolicy:
    policy = db.get(models.Policy, policy_id)
    if not policy or not (policy.is_baseline or policy.owner_id == current_user.id):
        raise PolicyNotFoundError(f"Policy {policy_id!r} not found.")
    return ResolvedPolicy(
        policy=policy,
        policy_headers=[PolicyHeaderIn(**h) for h in policy.headers],
        policy_name=policy.name,
        policy_version=f"v{policy.version}",
        csp_policy=CSPPolicy(**policy.csp_policy) if policy.csp_policy else None,
    )
