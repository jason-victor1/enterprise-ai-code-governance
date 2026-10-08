"""
policy_engine.py
----------------
Deterministic Python validator that mirrors and validates OPA/Rego invariants
against IAM policies and classifier output payloads.
"""
from typing import Dict, Any, List


class PolicyEvaluator:

    @staticmethod
    def evaluate_iam_policy(policy: Dict[str, Any]) -> List[str]:
        violations = []
        for stmt in policy.get("Statement", []):
            if stmt.get("Effect") == "Allow":
                actions = stmt.get("Action", [])
                if isinstance(actions, str):
                    actions = [actions]
                resource = stmt.get("Resource", "")

                # Check CRITICAL-IAM-01
                if "*" in actions:
                    violations.append(f"[CRITICAL-IAM-01] Statement '{stmt.get('Sid')}' grants wildcard action ('*').")

                # Check CRITICAL-IAM-02
                if "iam:PassRole" in actions and resource == "*":
                    violations.append(f"[CRITICAL-IAM-02] Statement '{stmt.get('Sid')}' allows unconstrained 'iam:PassRole'.")

        return violations

    @staticmethod
    def evaluate_governance_report(report: Dict[str, Any]) -> List[str]:
        violations = []
        tier = report["blast_radius"]["overall_tier"]
        author = report["author_metadata"]["author_type"]
        sec_approved = report["author_metadata"]["senior_security_approved"]

        if tier == 1 and not sec_approved:
            violations.append("[GOVERNANCE-TIER-01] Tier 1 critical path modified without mandatory Senior Security sign-off.")

        # Check Immutable Guards
        if author == "agent":
            for f in report["blast_radius"]["evaluated_files"]:
                p = f["path"]
                if p.startswith(".github/") or p.startswith("policies/") or p.endswith("requirements.txt"):
                    violations.append(f"[IMMUTABLE-GUARD-01] Agent identity attempted to modify protected path: '{p}'")

        return violations
