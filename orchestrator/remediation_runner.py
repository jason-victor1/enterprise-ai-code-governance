"""
remediation_runner.py
---------------------
Coordinates the remediation loop:
Triage Finding -> Fixer Agent -> Adversarial Auditor -> Circuit Breaker Gate.
"""
from typing import Dict, Any
from orchestrator.schemas import SecurityFinding
from orchestrator.fixer_agent import FixerAgent
from orchestrator.adversarial_auditor import AdversarialAuditor
from orchestrator.circuit_breaker import RemediationCircuitBreaker, CircuitBreakerOpenException


class RemediationOrchestrator:
    def __init__(self, max_turns: int = 2):
        self.circuit_breaker = RemediationCircuitBreaker(max_turns=max_turns)
        self.fixer = FixerAgent(offline_mode=True)
        self.auditor = AdversarialAuditor(offline_mode=True)

    def execute_remediation_cycle(self, finding: SecurityFinding, initial_code: str) -> Dict[str, Any]:
        audit_verdict = None
        patch = None
        history = []

        while True:
            try:
                self.circuit_breaker.check_can_proceed()
            except CircuitBreakerOpenException as e:
                return {
                    "status": "ESCALATED_TO_HUMAN",
                    "reason": str(e),
                    "total_turns": self.circuit_breaker.current_turn,
                    "history": history
                }

            # Turn tracking
            turn_meta = self.circuit_breaker.record_turn(tokens_used=1200)

            # 1. Generate Patch
            patch = self.fixer.generate_remediation(finding, initial_code)

            # 2. Context-Decoupled Adversarial Audit
            audit_verdict = self.auditor.audit_patch(patch)

            history.append({
                "turn": self.circuit_breaker.current_turn,
                "patch_description": patch.remediation_description,
                "audit_verdict": audit_verdict.model_dump()
            })

            # Check if Auditor Approved
            if audit_verdict.verdict == "APPROVED":
                return {
                    "status": "SUCCESSFULLY_REMEDIATED",
                    "total_turns": self.circuit_breaker.current_turn,
                    "final_patch": patch.model_dump(),
                    "final_verdict": audit_verdict.model_dump(),
                    "history": history
                }

            # If rejected and turn limit exceeded next check, loop breaks on next cycle
