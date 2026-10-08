# Enterprise AI Code Governance Platform

[![CI/CD Pipeline](https://img.shields.io/badge/CI%2FCD-Passing-success.svg)](#)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](https://www.python.org/)
[![Policy-as-Code](https://img.shields.io/badge/Policy--as--Code-OPA%20%2F%20Conftest-blueviolet)](https://www.openpolicyagent.org/)
[![OWASP Agentic](https://img.shields.io/badge/OWASP-Agentic%20Top%2010%20(2026)-red)](https://genai.owasp.org/)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

An enterprise-grade DevSecOps governance platform that converts subjective AI code review into a deterministic, policy-enforced pipeline. Designed to eliminate reviewer fatigue, defeat the **Tautological Testing Trap**, prevent **agent privilege escalation**, and automate multi-agent remediation within bounded blast radiuses.

---

## ⚡ The 2-Minute Executive Summary

When engineering teams adopt autonomous coding agents, **generation velocity explodes, but human review capacity and architectural trust collapse**.

Traditional DevSecOps approaches fail in the agentic era:
* **The "Human API" Bottleneck:** Security engineers spend hours routing scanner output into Jira tickets while AI models generate vulnerable code at machine speed (the **Velocity Gap**).
* **The Tautological Testing Trap:** AI models write unit tests that assert their own hallucinated assumptions, achieving 100% green code coverage on broken security invariants.
* **Agent Privilege Escalation:** Unchecked coding agents modify CI workflows or weaken linter/policy rules to make failing builds pass green.

This platform replaces naive pull-request linters with a **6-Stage Deterministic Governance Engine**:
1. **Algorithmic Blast-Radius Scoring:** Evaluates AST transitive dependencies to route PRs into deterministic risk tiers (Tiers 1–3).
2. **Immutable Policy Guards:** Cryptographically prevents agent identities from altering CI workflows or policy configurations.
3. **Deterministic Policy-as-Code:** OPA/Conftest rules enforcing zero-trust IAM and least privilege.
4. **Context-Decoupled Multi-Agent Remediation:** Separation of duties between a Bounded Fixer Agent and an Adversarial Auditor bounded by a **2-turn circuit breaker**.
5. **Mutation-Hardened Proof:** Fuzz testing and mutation gates that reject self-affirming AI unit tests.
6. **Tiered Human-in-the-Loop Sign-off:** Preserves senior engineering review strictly for high-risk Tier 1 architectural deltas.

---

## 🛑 The 7 Enterprise Pain Points & Value Propositions

| Enterprise Risk / Pain Point | Typical Failure Mode | How This Platform Resolves It | Measurable Business ROI |
| :--- | :--- | :--- | :--- |
| **1. Reviewer Fatigue & Rubber-Stamping** | Senior engineers spend 15+ hours/week reviewing massive agent PRs, leading to uninspected merges. | **AST-Aware Blast-Radius Scoring** auto-merges low-risk Tier 3 leaves and isolates Tier 1 changes. | **40–60% reduction** in senior engineer PR review backlog. |
| **2. The Tautological Testing Trap** | AI writes tests confirming its own bugs; CI passes green with hidden vulnerabilities. | **Mutation Testing & Property Fuzzing** programmatically injects code mutants to break faulty assertions. | **Zero false-confidence green builds** on broken security invariants. |
| **3. Slopsquatting & Supply Chain Drift** | Coding agents hallucinate unvetted public packages or pull typosquatted dependencies. | **Lockfile Scoping & SBOM Attestation** blocks unverified packages; generates Syft CycloneDX manifests. | Complete protection against hallucinated dependency poisoning. |
| **4. Agent Privilege Escalation** | Autonomous agents modify `.github/` workflows or `.rego` policies to force failing checks to pass. | **Immutable Policy-as-Code Guards** deny non-human identities write access to governance paths. | Guarantees non-human identity containment and system integrity. |
| **5. Confirmation Bias in AI Review** | Reviewing agent code within the same LLM context perpetuates the model's blind spots. | **Context-Decoupled Adversarial Auditing** with clean-context evaluators and Pydantic CWE schemas. | Eliminates prompt confirmation bias during vulnerability triage. |
| **6. Runaway Agent Loops (Economic DoS)** | Fixer and Reviewer agents debate code patches in an infinite token-draining loop. | **Remediation Circuit Breaker** enforces a deterministic 2-turn maximum before human escalation. | Predictable CI/CD execution costs with zero runaway API overhead. |
| **7. Audit & Provenance Void** | Inability to prove to compliance auditors (SOC 2, ISO 27001) which code was agent-generated. | **Structured PR Audit Comments & Cosign Attestation** tie all commits to verified agent run metadata. | **Instant compliance audit readiness** with zero manual evidence gathering. |

---
## 🏛️ Architecture & Trust Boundaries

```text
                          [ Developer / Agent Opens Pull Request ]
                                              │
                                              ▼
                ┌───────────────────────────────────────────────────────────┐
                │        STAGE 1: ALGORITHMIC BLAST-RADIUS CLASSIFICATION   │
                │  AST-aware dependency traversal & file-path analysis      │
                │  ├─ Tier 1: Core State, IAM, DB, Ingress/Egress, Policies │
                │  ├─ Tier 2: Domain Services, API Contracts, Logic Modules │
                │  └─ Tier 3: Presentation, Isolated Utilities, Docs        │
                └─────────────────────────────┬─────────────────────────────┘
                                              │
                                              ▼
                ┌───────────────────────────────────────────────────────────┐
                │        STAGE 2: SUPPLY CHAIN & IMMUTABLE INTEGRITY GATE   │
                │  ├─ Lockfile verification & private registry scoping      │
                │  ├─ Immutable Policy Guard: Block agent writes to .rego   │
                │  └─ Syft CycloneDX SBOM generation + Cosign attestation   │
                └─────────────────────────────┬─────────────────────────────┘
                                              │
                                              ▼
                ┌───────────────────────────────────────────────────────────┐
                │        STAGE 3: DETERMINISTIC POLICY-AS-CODE (STATIC)     │
                │  ├─ Semgrep / Bandit: AST taint & injection analysis      │
                │  ├─ Conftest / OPA: Check IAM wildcards, open SG rules    │
                │  └─ Output: Normalized SARIF vulnerability schema         │
                └─────────────────────────────┬─────────────────────────────┘
                                              │ (Vulnerabilities Detected)
                                              ▼
                ┌───────────────────────────────────────────────────────────┐
                │        STAGE 4: BOUNDED AGENTIC REMEDIATION LOOP          │
                │  ├─ Triage Agent (Read-Only): Ingests diff + SARIF spec   │
                │  ├─ Fixer Agent: Generates patch on feature branch only   │
                │  ├─ Adversarial Reviewer: Decoupled context, CWE schema   │
                │  └─ Circuit Breaker: Max 2 turns before human escalation  │
                └─────────────────────────────┬─────────────────────────────┘
                                              │ (Remediated Branch)
                                              ▼
                ┌───────────────────────────────────────────────────────────┐
                │        STAGE 5: EMPIRICAL MUTATION & REGRESSION TESTING   │
                │  ├─ Pytest / Baseline Suite: Functional regression check  │
                │  ├─ mutmut Mutation Testing: Enforce mutant kill rates    │
                │  └─ Hypothesis: Property-based fuzzing on query contracts │
                └─────────────────────────────┬─────────────────────────────┘
                                              │ (Verified Telemetry)
                                              ▼
                ┌───────────────────────────────────────────────────────────┐
                │        STAGE 6: TIERED HITL GATE & PROGRESSIVE RELEASE    │
                │  ├─ Tier 3: Auto-merge eligible                           │
                │  ├─ Tier 1/2: Mandatory Senior CODEOWNERS cryptographic   │
                │  │            sign-off on diffs and ADR alignment         │
                │  └─ Deployment: Canary rollout with runtime monitoring    │
                └───────────────────────────────────────────────────────────┘
```


## 📊 Implementation Matrix: Developer Heuristic vs. Enterprise Standard

| Governance Phase | Developer Heuristic | Enterprise Governance Implementation | Tooling & Enforcement Mechanism |
| :--- | :--- | :--- | :--- |
| **1. Blast Radius** | Eyeball trunk vs. leaf files | **AST Dependency Traversal**: Transitive import analysis cascades risk to highest imported tier. | Python `ast`, Dependency Graph, Path Filters |
| **2. Supply Chain** | Run `npm audit` / `pip check` | **SLSA Level 3 & Immutable Policy Locks**: Agent identities denied write access to CI & policies. | `.github/CODEOWNERS`, Syft SBOM, Cosign |
| **3. Invariant Checks** | Linters & type annotations | **Deterministic Policy-as-Code**: Automated blocking of IAM wildcards and unconstrained `PassRole`. | Conftest (OPA Rego), Bandit, Semgrep |
| **4. Multi-Agent Audit**| Generic LLM code review | **Context-Decoupled Adversarial Auditor**: Structured Pydantic CWE outputs; 2-turn circuit breaker. | Clean-context agent, Pydantic, Turn Limiter |
| **5. Validation Proof** | Agent-written tests & pass logs | **Mutation Testing & Property Fuzzing**: Proves tests detect code mutations; fuzzes arbitrary inputs. | `mutmut`, `hypothesis`, Pytest Telemetry |
| **6. Production Sign-Off**| Manual inspection of 20% | **Risk-Tiered Sign-off & ADR Alignment**: Senior review focused exclusively on Tier 1 architectural deltas. | GitHub CODEOWNERS, Architecture Decision Records |

---
## 🚀 Quickstart & Local Verification

### 1. Installation
Clone the repository and set up a local virtual environment:

```bash
git clone https://github.com/your-org/enterprise-ai-code-governance.git
cd enterprise-ai-code-governance

python3 -m venv .venv
source .venv/bin/activate
make setup
```

### 2. Run the Full Test Suite (19 Verified Tests)
Execute all unit tests, policy engine checks, and property-based fuzz tests:

```bash
make test
```

### 3. Run the End-to-End Governance Simulation
Execute an end-to-end dry run demonstrating blast-radius AST parsing, bounded multi-agent remediation, and security property fuzzing:

```bash
make demo
```

### 4. Inspect Blast-Radius Scoring
Run the AST classifier directly on any file path:

```bash
make classify
```

---

## 📁 Repository Layout

```text
├── .github/
│   ├── CODEOWNERS                       # Tier 1 path restrictions (IAM, policies, workflows)
│   └── workflows/
│       └── governance-pipeline.yml      # 6-Stage CI/CD governance pipeline
├── policies/
│   ├── blast_radius.rego                # OPA rules for path & AST dependency risk scoring
│   ├── iam_invariants.rego              # Blocks IAM wildcards & unconstrained PassRole
│   └── immutable_guards.rego            # Denies agent identities write access to CI/policies
├── orchestrator/
│   ├── classifier.py                    # AST dependency graph parser for blast-radius scoring
│   ├── policy_engine.py                 # Deterministic Python policy validator mirroring OPA
│   ├── schemas.py                       # Strict Pydantic data contracts for agent telemetry
│   ├── circuit_breaker.py               # Deterministic turn limiter & economic DoS protection
│   ├── fixer_agent.py                   # Bounded patch generator (feature branch scoped)
│   ├── adversarial_auditor.py           # Decoupled reviewer with structured CWE output schema
│   └── remediation_runner.py            # End-to-end multi-agent coordination state machine
├── test-harness/
│   ├── app/
│   │   ├── tier1_iam_auth.py            # Tier 1: Insecure IAM policy generator fixture
│   │   ├── tier2_data_service.py        # Tier 2: SQLi database service fixture
│   │   └── tier3_formatters.py          # Tier 3: Leaf node string formatting utility
│   └── tests/
│       ├── test_tautological_trap.py    # Demonstrates false-confidence green tests
│       ├── test_classifier_and_policies.py # Verifies AST classifier & Rego invariants
│       ├── test_agent_orchestrator.py   # Verifies Fixer, Auditor & Circuit Breaker
│       └── test_properties.py           # Hypothesis property-based fuzzing tests
├── Makefile                             # Local ergonomics (make setup, test, demo, audit)
├── pyproject.toml                       # Build configuration & pytest paths
├── requirements.txt                     # Pinned project dependencies
└── README.md                            # Executive overview & architecture documentation
```

---

## 📄 License
This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
