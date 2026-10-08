from app.tier1_iam_auth import IAMPolicyGenerator


def test_service_role_policy_generation():
    policy = IAMPolicyGenerator.generate_service_role_policy("s3", allow_all_actions=False)
    assert policy["Version"] == "2012-10-17"
    assert len(policy["Statement"]) == 2
    
    # Verify scoped action prefix
    actions = policy["Statement"][0]["Action"]
    assert "s3:Get*" in actions
    assert "*" not in actions


def test_insecure_wildcard_generation():
    # Verifies the generation path that Conftest/Rego will block
    policy = IAMPolicyGenerator.generate_service_role_policy("s3", allow_all_actions=True)
    assert policy["Statement"][0]["Action"] == ["*"]
