"""
BenchmarkFixtures - Creates controlled synthetic benchmark repos with ground truth metadata (M8).
"""

import os
import shutil
import tempfile
from typing import List, Tuple

from agentos_swe.benchmark.models import GroundTruthCase, ExpectedStatus


class BenchmarkFixtures:
    """
    Generates structured benchmark target workspace containing known flaws and ground truth metadata.
    """

    @staticmethod
    def create_benchmark_workspace() -> Tuple[str, List[GroundTruthCase]]:
        temp_dir = tempfile.mkdtemp(prefix="agentos_swe_benchmark_")

        # 1. Bug Case: Mutable default argument in app.py
        app_py = os.path.join(temp_dir, "app.py")
        with open(app_py, "w", encoding="utf-8") as f:
            f.write(
                "import shlex\n\n"
                "def process_items(items=[]):\n"
                "    items.append('processed')\n"
                "    return items\n\n"
                "def safe_execute(command):\n"
                "    # Safe quote\n"
                "    return shlex.quote(command)\n"
            )

        # 2. Security Case: Unsafe eval usage in auth.py
        auth_py = os.path.join(temp_dir, "auth.py")
        with open(auth_py, "w", encoding="utf-8") as f:
            f.write(
                "def evaluate_token(token_str):\n"
                "    # Security flaw: eval usage\n"
                "    return eval(token_str)\n"
            )

        # 3. Performance Case: N+1 query loop in db.py
        db_py = os.path.join(temp_dir, "db.py")
        with open(db_py, "w", encoding="utf-8") as f:
            f.write(
                "def fetch_user_details(user_ids):\n"
                "    results = []\n"
                "    for uid in user_ids:\n"
                "        # N+1 query loop flaw\n"
                "        results.append(fetch_one_user(uid))\n"
                "    return results\n\n"
                "def fetch_one_user(uid):\n"
                "    return {'id': uid}\n"
            )

        # 4. Architecture Case: Circular import between mod_a and mod_b
        mod_a = os.path.join(temp_dir, "mod_a.py")
        with open(mod_a, "w", encoding="utf-8") as f:
            f.write("import mod_b\nclass A:\n    pass\n")

        mod_b = os.path.join(temp_dir, "mod_b.py")
        with open(mod_b, "w", encoding="utf-8") as f:
            f.write("import mod_a\nclass B:\n    pass\n")

        # 5. Reproduction Test File
        test_py = os.path.join(temp_dir, "test_app.py")
        with open(test_py, "w", encoding="utf-8") as f:
            f.write(
                "import unittest\n"
                "class TestBenchmark(unittest.TestCase):\n"
                "    def test_sample(self): self.assertTrue(True)\n"
            )

        # Ground Truth Metadata List
        ground_truth_cases = [
            GroundTruthCase(
                case_id="gt_bug_01",
                category="bug",
                file="app.py",
                line=3,
                title="Mutable Default Argument",
                expected_status=ExpectedStatus.TRUE_POSITIVE,
                expected_fix_file="app.py",
                description="process_items uses mutable list default argument",
            ),
            GroundTruthCase(
                case_id="gt_sec_01",
                category="security",
                file="auth.py",
                line=3,
                title="Unsafe Eval Execution",
                expected_status=ExpectedStatus.TRUE_POSITIVE,
                expected_fix_file="auth.py",
                description="evaluate_token executes arbitrary code via eval()",
            ),
            GroundTruthCase(
                case_id="gt_perf_01",
                category="performance",
                file="db.py",
                line=3,
                title="N+1 Database Query Loop",
                expected_status=ExpectedStatus.TRUE_POSITIVE,
                expected_fix_file="db.py",
                description="fetch_user_details issues individual queries inside loop",
            ),
            GroundTruthCase(
                case_id="gt_arch_01",
                category="architecture",
                file="mod_a.py",
                line=1,
                title="Circular Module Dependency",
                expected_status=ExpectedStatus.TRUE_POSITIVE,
                expected_fix_file="mod_a.py",
                description="mod_a and mod_b contain circular import dependency",
            ),
            GroundTruthCase(
                case_id="gt_fp_01",
                category="security",
                file="app.py",
                line=7,
                title="Sanitized Command Execution Claim",
                expected_status=ExpectedStatus.FALSE_POSITIVE,
                expected_fix_file="",
                description="Command execution is safely sanitized via shlex.quote",
            ),
            GroundTruthCase(
                case_id="gt_inc_01",
                category="performance",
                file="app.py",
                line=1,
                title="Ambiguous Performance Claim",
                expected_status=ExpectedStatus.INCONCLUSIVE,
                expected_fix_file="",
                description="Unverified performance claim without test reproduction",
            ),
        ]

        return temp_dir, ground_truth_cases
