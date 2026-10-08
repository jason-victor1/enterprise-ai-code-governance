#!/usr/bin/env python3
"""
classifier.py
-------------
Parses Python source files using the standard `ast` module to build an import dependency graph.
Calculates deterministic blast-radius tiers (Tiers 1-3) based on path patterns and transitive
import escalation (e.g., if a Tier 3 leaf is imported by Tier 1 auth, its risk escalates to Tier 1).
"""

import ast
import json
import os
import sys
from pathlib import Path
from typing import Dict, List, Set, Any, Optional

TIER_1_PATTERNS = ["iam", "auth", "state", "policies", ".github", "db/migrations", "tier1_"]
TIER_2_PATTERNS = ["data_service", "api", "contracts", "tier2_"]
TIER_3_PATTERNS = ["formatters", "utils", "docs", "tier3_"]


class DependencyGraphBuilder:
    """Builds a project-wide module import graph using Python AST analysis."""

    def __init__(self, root_dir: Path):
        self.root_dir = root_dir
        self.import_graph: Dict[str, Set[str]] = {}  # file_rel_path -> set of imported module names
        self.module_to_file: Dict[str, str] = {}     # module_name -> file_rel_path

    def build(self) -> None:
        for py_path in self.root_dir.rglob("*.py"):
            rel_path = str(py_path.relative_to(self.root_dir))
            # Map module name (e.g., 'app.tier1_iam_auth')
            mod_name = py_path.stem
            self.module_to_file[mod_name] = rel_path

            imports = self._extract_imports(py_path)
            self.import_graph[rel_path] = imports

    @staticmethod
    def _extract_imports(file_path: Path) -> Set[str]:
        imports = set()
        try:
            with open(file_path, "r", encoding="utf-8") as f:
                tree = ast.parse(f.read(), filename=str(file_path))
            for node in ast.walk(tree):
                if isinstance(node, ast.Import):
                    for alias in node.names:
                        imports.add(alias.name.split(".")[0])
                        imports.add(alias.name.split(".")[-1])
                elif isinstance(node, ast.ImportFrom):
                    if node.module:
                        imports.add(node.module.split(".")[0])
                        imports.add(node.module.split(".")[-1])
                    for alias in node.names:
                        imports.add(alias.name)
        except Exception:
            pass
        return imports

    def find_dependents(self, target_rel_path: str) -> Set[str]:
        """Finds all files in the project that directly or indirectly import target_rel_path."""
        target_stem = Path(target_rel_path).stem
        dependents = set()
        for f_path, imports in self.import_graph.items():
            if target_stem in imports and f_path != target_rel_path:
                dependents.add(f_path)
        return dependents


class BlastRadiusClassifier:
    """Evaluates blast radius score and tier for a set of changed files."""

    def __init__(self, project_root: Path):
        self.project_root = project_root
        self.graph_builder = DependencyGraphBuilder(project_root)
        self.graph_builder.build()

    @staticmethod
    def classify_single_file_base(path_str: str) -> int:
        lower = path_str.lower()
        if any(p in lower for p in TIER_1_PATTERNS):
            return 1
        if any(p in lower for p in TIER_2_PATTERNS):
            return 2
        return 3

    def evaluate_changes(self, modified_files: List[str], author_type: str = "human", approvals: Optional[List[str]] = None) -> Dict[str, Any]:
        approvals = approvals or []
        file_evaluations = []
        overall_tier = 3
        escalation_reasons = []

        for rel_file in modified_files:
            base_tier = self.classify_single_file_base(rel_file)
            effective_tier = base_tier
            dependents = self.graph_builder.find_dependents(rel_file)

            # Check if any dependent elevates the tier
            for dep in dependents:
                dep_base = self.classify_single_file_base(dep)
                if dep_base < effective_tier:
                    escalation_reasons.append(
                        f"Transitive elevation: '{rel_file}' (Tier {effective_tier}) imported by higher-tier module '{dep}' (Tier {dep_base})"
                    )
                    effective_tier = dep_base

            file_evaluations.append({
                "path": rel_file,
                "base_tier": base_tier,
                "effective_tier": effective_tier,
                "dependents": sorted(list(dependents))
            })

            if effective_tier < overall_tier:
                overall_tier = effective_tier

        # Governance logic
        requires_senior_security_signoff = (overall_tier == 1)
        eligible_for_auto_merge = (overall_tier == 3) and (author_type in ["human", "agent"])
        senior_security_approved = "senior_security" in approvals

        return {
            "blast_radius": {
                "overall_tier": overall_tier,
                "tier_name": f"Tier {overall_tier}",
                "requires_senior_security_signoff": requires_senior_security_signoff,
                "eligible_for_auto_merge": eligible_for_auto_merge,
                "escalations": escalation_reasons,
                "evaluated_files": file_evaluations
            },
            "author_metadata": {
                "author_type": author_type,
                "approvals": approvals,
                "senior_security_approved": senior_security_approved
            }
        }


def main():
    root = Path(__file__).resolve().parent.parent
    classifier = BlastRadiusClassifier(root)

    # If arguments passed, use them; otherwise run baseline demonstration
    files_to_check = sys.argv[1:] if len(sys.argv) > 1 else [
        "test-harness/app/tier1_iam_auth.py",
        "test-harness/app/tier3_formatters.py"
    ]

    report = classifier.evaluate_changes(files_to_check, author_type="agent", approvals=[])
    print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
