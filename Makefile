.PHONY: help setup test classify audit demo clean

PYTHON ?= python3
PIP ?= pip
PYTEST ?= pytest

help:
	@echo "Enterprise AI Code Governance Platform"
	@echo "---------------------------------------"
	@echo "make setup     - Install dependencies into active virtual environment"
	@echo "make test      - Run all 19 unit, invariant, and property fuzz tests"
	@echo "make classify  - Execute AST blast-radius dependency analysis"
	@echo "make audit     - Evaluate IAM and governance policy invariants"
	@echo "make demo      - Run full end-to-end multi-agent governance simulation"
	@echo "make clean     - Remove cache directories and temporary artifacts"

setup:
	$(PIP) install --upgrade pip
	$(PIP) install -r requirements.txt

test:
	$(PYTEST) test-harness/tests/

classify:
	$(PYTHON) orchestrator/classifier.py

audit:
	@echo "--> Running IAM Policy Invariant Checks..."
	$(PYTHON) -c "from app.tier1_iam_auth import IAMPolicyGenerator; from orchestrator.policy_engine import PolicyEvaluator; p = IAMPolicyGenerator.generate_service_role_policy('s3', True); print(PolicyEvaluator.evaluate_iam_policy(p))"

demo:
	@echo "=================================================================="
	@echo "  ENTERPRISE AI CODE GOVERNANCE PLATFORM: END-TO-END DEMO"
	@echo "=================================================================="
	@echo "\n[Step 1] Classifying modified paths via AST dependency analysis..."
	$(PYTHON) orchestrator/classifier.py
	@echo "\n[Step 2] Executing Bounded Multi-Agent Remediation Loop..."
	$(PYTHON) -c "from orchestrator.schemas import SecurityFinding; from orchestrator.remediation_runner import RemediationOrchestrator; orch = RemediationOrchestrator(max_turns=2); f = SecurityFinding(cwe_id='CWE-89', owasp_category='A03:2021-Injection', severity='HIGH', file_path='test-harness/app/tier2_data_service.py', vulnerability_description='SQLi via string interpolation', exploit_scenario='Raw string input'); res = orch.execute_remediation_cycle(f, ''); import json; print(json.dumps(res, indent=2))"
	@echo "\n[Step 3] Verifying Security Invariants & Property Fuzz Tests..."
	$(PYTEST) test-harness/tests/test_properties.py
	@echo "\n[✓] End-to-End Governance Simulation Completed Successfully."

clean:
	rm -rf .pytest_cache .hypothesis .tmp_yt_extraction build dist *.egg-info *.json *.xml
	find . -type d -name "__pycache__" -exec rm -rf {} +
