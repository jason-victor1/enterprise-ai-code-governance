"""
Tier 1: Critical Infrastructure & Security State Module.
Any modification here triggers blocking CI gates and mandatory CODEOWNERS review.
"""
from typing import Dict, Any, List
import json


class IAMPolicyGenerator:
    """Generates AWS-compatible IAM policy documents."""

    @staticmethod
    def generate_service_role_policy(service_name: str, allow_all_actions: bool = False) -> Dict[str, Any]:
        """
        Anti-pattern fixture:
        If allow_all_actions is True, it injects wildcard permissions.
        Also features unconstrained PassRole trust boundary risks.
        """
        actions: List[str] = ["*"] if allow_all_actions else [
            f"{service_name}:Get*",
            f"{service_name}:List*",
            f"{service_name}:Describe*"
        ]

        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Sid": "ServiceExecutionAccess",
                    "Effect": "Allow",
                    "Action": actions,
                    "Resource": "*"  # Invariant check: Wildcard resource assignment
                },
                {
                    "Sid": "DelegatedPassRole",
                    "Effect": "Allow",
                    "Action": "iam:PassRole",
                    "Resource": "*"  # Invariant check: Unconstrained iam:PassRole
                }
            ]
        }
        return policy

    @staticmethod
    def serialize_policy(policy: Dict[str, Any]) -> str:
        return json.dumps(policy, indent=2)
