import pytest
from orchestrator.schemas import SecurityFinding, RemediationPatch
from orchestrator.circuit_breaker import RemediationCircuitBreaker, CircuitBreakerOpenException
from orchestrator.fixer_agent import FixerAgent
from orchestrator.adversarial_auditor import AdversarialAuditor
from orchestrator.remediation_runner import RemediationOrchestrator


def test_circuit_breaker_enforces_max_turns():
    cb = RemediationCircuitBreaker(max_turns=2)
    
    # Turn 1
    res1 = cb.record_turn(1000)
    assert res1["status"] == "HEALTHY"
    assert cb.is_tripped is False

    # Turn 2
    res2 = cb.record_turn(1000)
    assert res2["status"] == "HEALTHY"
    assert cb.is_tripped is False

    # Turn 3 (Exceeds max 2 turns)
    res3 = cb.record_turn(1000)
    assert res3["status"] == "TRIPPED_MAX_TURNS"
    assert cb.is_tripped is True

    # Check that exception is raised on subsequent run
    with pytest.raises(CircuitBreakerOpenException):
        cb.check_can_proceed()


def test_fixer_and_auditor_approval_cycle():
    finding = SecurityFinding(
        cwe_id="CWE-89",
        owasp_category="A03:2021-Injection",
        severity="HIGH",
        file_path="test-harness/app/tier2_data_service.py",
        line_number=35,
        vulnerability_description="SQL injection via raw string formatting",
        exploit_scenario="Attacker supplies ' OR 1=1 to dump users table"
    )

    fixer = FixerAgent(offline_mode=True)
    patch = fixer.generate_remediation(finding, "")
    assert patch.confidence_score > 0.90
    assert "?" in patch.patched_code_snippet

    auditor = AdversarialAuditor(offline_mode=True)
    verdict = auditor.audit_patch(patch)
    assert verdict.verdict == "APPROVED"
    assert verdict.residual_risk_score <= 10
    assert len(verdict.cwe_violations_remaining) == 0


def test_auditor_rejects_insecure_patch():
    auditor = AdversarialAuditor(offline_mode=True)
    # A flawed patch that continues using string interpolation
    insecure_patch = RemediationPatch(
        file_path="app/tier2_data_service.py",
        target_function="insecure_func",
        remediation_description="Fake fix that still interpolates strings",
        original_code_snippet="old code",
        patched_code_snippet="cursor.execute(f'SELECT * FROM users WHERE username = \"{username}\"')",
        confidence_score=0.4
    )
    verdict = auditor.audit_patch(insecure_patch)
    assert verdict.verdict == "REJECTED"
    assert verdict.residual_risk_score >= 80
    assert any("CWE-89" in v for v in verdict.cwe_violations_remaining)


def test_remediation_orchestrator_end_to_end():
    orchestrator = RemediationOrchestrator(max_turns=2)
    finding = SecurityFinding(
        cwe_id="CWE-89",
        owasp_category="A03:2021-Injection",
        severity="HIGH",
        file_path="test-harness/app/tier2_data_service.py",
        line_number=35,
        vulnerability_description="SQL injection vulnerability",
        exploit_scenario="Arbitrary user data extraction"
    )
    result = orchestrator.execute_remediation_cycle(finding, "vulnerable source code")
    assert result["status"] == "SUCCESSFULLY_REMEDIATED"
    assert result["total_turns"] == 1
    assert result["final_verdict"]["verdict"] == "APPROVED"
