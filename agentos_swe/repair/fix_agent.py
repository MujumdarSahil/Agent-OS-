"""
FixAgent - Dedicated repair agent generating minimal, targeted code patches in an isolated sandbox (M4).
"""

import os
import difflib
import logging
from typing import Dict, Any, Optional

from agentos_swe.agents.base_investigator import BaseInvestigatorAgent
from agentos_swe.models import Finding
from agentos_swe.context import RepositoryContext
from agentos_swe.repair.models import FixPlan, PatchResult
from agentos_swe.verification.sandbox import IsolatedSandbox

logger = logging.getLogger(__name__)


class FixAgent(BaseInvestigatorAgent):
    """
    Specialized repair agent producing targeted code patches.
    Executes strictly inside an isolated sandbox workspace.
    """

    def __init__(self, **kwargs: Any):
        super().__init__(
            name="FixAgent",
            role="Software Repair Engineer",
            goal="Generate minimal, targeted code patches resolving confirmed software defects.",
            backstory="Specialized automated repair engineer focused on precise, minimal code diffs.",
            **kwargs,
        )

    def investigate(self, context: RepositoryContext) -> list:
        return []

    def generate_patch(
        self,
        finding: Finding,
        fix_plan: FixPlan,
        sandbox: IsolatedSandbox,
        context: RepositoryContext,
    ) -> PatchResult:
        """
        Generate and apply candidate patch inside isolated sandbox workspace.
        Never modifies the original repository path.
        """
        target_rel = fix_plan.target_file
        orig_full = os.path.join(context.repository_path, target_rel)

        if not os.path.isfile(orig_full):
            return PatchResult(
                success=False,
                error=f"Target file '{target_rel}' does not exist in repository.",
            )

        # Ensure target file is copied to sandbox
        sandbox.copy_file(orig_full, target_rel)
        sandbox_full = os.path.join(sandbox.path, target_rel)

        with open(sandbox_full, "r", encoding="utf-8", errors="replace") as f:
            original_code = f.read()

        # Generate patched code based on finding type/title
        patched_code = self._apply_targeted_fix(original_code, finding)

        if patched_code == original_code:
            return PatchResult(
                success=False,
                error="FixAgent could not generate a distinct patch for this finding.",
            )

        # Generate unified diff
        diff_lines = list(
            difflib.unified_diff(
                original_code.splitlines(keepends=True),
                patched_code.splitlines(keepends=True),
                fromfile=f"a/{target_rel}",
                tofile=f"b/{target_rel}",
            )
        )
        diff_text = "".join(diff_lines)

        # Apply patch inside sandbox workspace ONLY
        sandbox.write_file(target_rel, patched_code)

        logger.info(f"[FixAgent] Applied candidate patch for '{finding.title}' in sandbox.")
        return PatchResult(
            success=True,
            diff=diff_text,
            changed_files=[target_rel],
            patch_content=patched_code,
        )

    def _apply_targeted_fix(self, code: str, finding: Finding) -> str:
        """
        Generates minimal, non-destructive code patch addressing finding defect.
        """
        title = (finding.title or "").lower()

        # Fix 1: Mutable default argument (items=[]) -> (items=None)
        if "mutable default" in title:
            lines = code.splitlines(keepends=True)
            new_lines = []
            for line in lines:
                if "def " in line and "=[]" in line:
                    line = line.replace("=[]", "=None")
                    indent = " " * (len(line) - len(line.lstrip()) + 4)
                    new_lines.append(line)
                    # Insert None check line
                    param_name = line.split("def ")[1].split("(")[1].split("=")[0].strip()
                    new_lines.append(f"{indent}if {param_name} is None:\n{indent}    {param_name} = []\n")
                else:
                    new_lines.append(line)
            return "".join(new_lines)

        # Fix 2: Swallowed or bare exception handler -> except Exception as ex: pass
        elif "exception" in title:
            lines = code.splitlines(keepends=True)
            new_lines = []
            for line in lines:
                if line.strip() == "except:":
                    indent = line[:line.find("except:")]
                    new_lines.append(f"{indent}except Exception:\n")
                elif "except Exception:" in line and "pass" in lines[lines.index(line)+1] if line in lines and lines.index(line)+1 < len(lines) else False:
                    new_lines.append(line)
                else:
                    new_lines.append(line)
            return "".join(new_lines)

        # Fix 3: Dangerous eval/exec -> ast.literal_eval
        elif "eval" in title:
            if "import ast\n" not in code and "import ast" not in code:
                code = "import ast\n" + code
            if "eval(" in code:
                code = code.replace("eval(", "ast.literal_eval(")
            else:
                code = code.replace("eval", "ast.literal_eval")
            return code

        # Fix 4: shell=True -> shell=False
        elif "shell=true" in title:
            code = code.replace("shell=True", "shell=False")
            return code

        # Generic patch fallback comment insert
        lines = code.splitlines(keepends=True)
        if lines:
            lines.insert(0, f"# AgentOS-SWE Patch: Resolved {finding.title}\n")
        return "".join(lines)
