"""
circuit_breaker.py
------------------
Deterministic turn limiter and token-expenditure guard.
Guarantees that autonomous multi-agent remediation loops terminate cleanly
within a maximum number of cycles (default: 2 turns) without runaway API costs.
"""
from typing import Dict, Any


class CircuitBreakerOpenException(Exception):
    """Raised when maximum remediation attempts are exceeded."""
    pass


class RemediationCircuitBreaker:
    def __init__(self, max_turns: int = 2, max_budget_tokens: int = 15000):
        self.max_turns = max_turns
        self.max_budget_tokens = max_budget_tokens
        self.current_turn = 0
        self.accumulated_tokens = 0
        self.is_tripped = False

    def record_turn(self, tokens_used: int = 1000) -> Dict[str, Any]:
        self.current_turn += 1
        self.accumulated_tokens += tokens_used

        if self.current_turn > self.max_turns:
            self.is_tripped = True
            return {
                "status": "TRIPPED_MAX_TURNS",
                "current_turn": self.current_turn,
                "message": f"Circuit breaker tripped: Exceeded max allowed turns ({self.max_turns}). Escalating to Tier 1 Security Engineer."
            }

        if self.accumulated_tokens > self.max_budget_tokens:
            self.is_tripped = True
            return {
                "status": "TRIPPED_TOKEN_BUDGET",
                "accumulated_tokens": self.accumulated_tokens,
                "message": f"Circuit breaker tripped: Token budget ({self.max_budget_tokens}) exceeded."
            }

        return {
            "status": "HEALTHY",
            "current_turn": self.current_turn,
            "turns_remaining": self.max_turns - self.current_turn
        }

    def check_can_proceed(self) -> None:
        if self.is_tripped or self.current_turn >= self.max_turns:
            raise CircuitBreakerOpenException(
                f"Remediation halted by Circuit Breaker at turn {self.current_turn}. Manual human triage required."
            )
