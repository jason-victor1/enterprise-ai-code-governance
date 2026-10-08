from pathlib import Path
from orchestrator.classifier import BlastRadiusClassifier
from orchestrator.policy_engine import PolicyEvaluator
from app.tier1_iam_auth import IAMPolicyGenerator


def test_classifier_tier3_leaf():
    root = Path(__file__).resolve().parent.parent.parent
    classifier = BlastRadiusClassifier(root)
    result = classifier.evaluate_changes(["test-harness/app/tier3_formatters.py"], author_type="human")

    assert result["blast_radius"]["overall_tier"] == 3
    assert result["blast_radius"]["requires_senior_security_signoff"] is False
    assert result["blast_radius"]["eligible_for_auto_merge"] is True


def test_classifier_tier1_iam():
    root = Path(__file__).resolve().parent.parent.parent
    classifier = BlastRadiusClassifier(root)
    result = classifier.evaluate_changes(["test-harness/app/tier1_iam_auth.py"], author_type="agent")

    assert result["blast_radius"]["overall_tier"] == 1
    assert result["blast_radius"]["requires_senior_security_signoff"] is True
    assert result["blast_radius"]["eligible_for_auto_merge"] is False


def test_policy_evaluator_iam_invariants_blocked():
    insecure_policy = IAMPolicyGenerator.generate_service_role_policy("s3", allow_all_actions=True)
    violations = PolicyEvaluator.evaluate_iam_policy(insecure_policy)

    assert len(violations) == 2
    assert any("[CRITICAL-IAM-01]" in v for v in violations)
    assert any("[CRITICAL-IAM-02]" in v for v in violations)


def test_policy_evaluator_iam_invariants_allowed():
    secure_policy = IAMPolicyGenerator.generate_service_role_policy("s3", allow_all_actions=False)
    violations = PolicyEvaluator.evaluate_iam_policy(secure_policy)

    # PassRole still has Resource: * in the generator fixture, confirming boundary detection
    assert any("[CRITICAL-IAM-02]" in v for v in violations)
    # But wildcard action is successfully eliminated
    assert not any("[CRITICAL-IAM-01]" in v for v in violations)


def test_immutable_guard_blocks_agent_tampering():
    root = Path(__file__).resolve().parent.parent.parent
    classifier = BlastRadiusClassifier(root)
    # Agent tries to modify a policy file
    report = classifier.evaluate_changes(["policies/blast_radius.rego"], author_type="agent")
    violations = PolicyEvaluator.evaluate_governance_report(report)

    assert any("[IMMUTABLE-GUARD-01]" in v for v in violations)
