"""
schemas.py
----------
Strict Pydantic data contracts for multi-agent communication.
Enforces typed structured outputs for findings, remediation patches, and audit verdicts.
"""
from typing import List, Optional
from pydantic import BaseModel, Field


class SecurityFinding(BaseModel):
    cwe_id: str = Field(description="Common Weakness Enumeration ID, e.g. CWE-89")
    owasp_category: str = Field(description="OWASP category, e.g. A03:2021-Injection")
    severity: str = Field(description="CRITICAL, HIGH, MEDIUM, LOW")
    file_path: str
    line_number: Optional[int] = None
    vulnerability_description: str
    exploit_scenario: str


class RemediationPatch(BaseModel):
    file_path: str
    target_function: str
    remediation_description: str
    original_code_snippet: str
    patched_code_snippet: str
    confidence_score: float = Field(ge=0.0, le=1.0)


class AuditVerdict(BaseModel):
    verdict: str = Field(description="APPROVED or REJECTED")
    residual_risk_score: int = Field(ge=0, le=100, description="0 is completely safe, 100 is critical risk")
    cwe_violations_remaining: List[str] = Field(default_factory=list)
    adversarial_feedback: str
    requires_human_escalation: bool = False
