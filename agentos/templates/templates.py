"""
templates.py — Phase 4 Workstream B: Bundled AgentOS Templates

Provides discovery and installation of pre-built crew templates.
Templates are stored as .agentpack files built from source YAML in agentos/templates/source/.

Install logic reuses Phase 3's pack_format.install_pack() exactly — no new install code.
"""

import os
from typing import List, Dict, Any, Optional

# Path to pre-built template packs (built by build_templates.py)
TEMPLATES_DIR = os.path.join(os.path.dirname(__file__), "packs")
TEMPLATES_SOURCE_DIR = os.path.join(os.path.dirname(__file__), "source")


# Template metadata — single source of truth for all bundled templates
BUNDLED_TEMPLATES: List[Dict[str, Any]] = [
    {
        "name": "research_assistant",
        "display_name": "Research Assistant",
        "description": "A two-agent crew (Researcher + Writer) that researches any topic and produces a polished report. Perfect starting crew for knowledge work.",
        "agents": ["Researcher", "Writer"],
        "crews": ["research_assistant_crew"],
        "missions": ["research_report"],
        "license_type": "free",
        "tags": ["research", "writing", "beginner-friendly"],
    },
    {
        "name": "code_review",
        "display_name": "Code Review",
        "description": "A two-agent crew (CodeReviewer + ReviewReporter) that reviews code for bugs, security issues, and quality, then formats findings into a prioritized report.",
        "agents": ["CodeReviewer", "ReviewReporter"],
        "crews": ["code_review_crew"],
        "missions": ["review_code"],
        "license_type": "free",
        "tags": ["engineering", "code-quality", "security"],
    },
    {
        "name": "customer_support",
        "display_name": "Customer Support Triage",
        "description": "A two-agent crew (Classifier + Responder) that triages incoming support tickets by priority and drafts empathetic, actionable responses.",
        "agents": ["Classifier", "Responder"],
        "crews": ["customer_support_crew"],
        "missions": ["triage_ticket"],
        "license_type": "free",
        "tags": ["support", "customer-success", "triage"],
    },
    {
        "name": "content_repurposing",
        "display_name": "Content Repurposing",
        "description": "A two-agent crew (ContentAnalyzer + SocialWriter) that transforms long-form content into optimized social media posts for Twitter/X, LinkedIn, and more.",
        "agents": ["ContentAnalyzer", "SocialWriter"],
        "crews": ["content_repurposing_crew"],
        "missions": ["repurpose_content"],
        "license_type": "free",
        "tags": ["content", "social-media", "marketing"],
    },
    {
        "name": "data_analysis",
        "display_name": "Data Analysis",
        "description": "A two-agent crew (DataExplorer + InsightSummarizer) that analyzes datasets and produces business intelligence reports with prioritized recommendations.",
        "agents": ["DataExplorer", "InsightSummarizer"],
        "crews": ["data_analysis_crew"],
        "missions": ["analyze_dataset"],
        "license_type": "free",
        "tags": ["data", "analytics", "business-intelligence"],
    },
    {
        "name": "task_planner",
        "display_name": "Personal Task Planner",
        "description": "A two-agent crew (TaskPlanner + TaskExecutor) that breaks down any goal into a structured plan with dependencies, then creates a concrete day-one execution checklist.",
        "agents": ["TaskPlanner", "TaskExecutor"],
        "crews": ["task_planner_crew"],
        "missions": ["plan_goal"],
        "license_type": "free",
        "tags": ["productivity", "planning", "beginner-friendly"],
    },
]


def list_templates() -> List[Dict[str, Any]]:
    """
    Return all bundled templates with their metadata.
    Checks whether the pre-built .agentpack file exists for each.
    """
    result = []
    for tmpl in BUNDLED_TEMPLATES:
        pack_path = _pack_path(tmpl["name"])
        result.append({
            **tmpl,
            "pack_available": os.path.exists(pack_path),
            "pack_path": pack_path,
        })
    return result


def get_template(name: str) -> Optional[Dict[str, Any]]:
    """Get a single template metadata dict by name. Returns None if not found."""
    for tmpl in BUNDLED_TEMPLATES:
        if tmpl["name"] == name:
            pack_path = _pack_path(name)
            return {**tmpl, "pack_available": os.path.exists(pack_path), "pack_path": pack_path}
    return None


def install_template(
    template_name: str,
    target_project: str,
    force: bool = False,
) -> Dict[str, Any]:
    """
    Install a bundled template into a target AgentOS project.

    This is a thin wrapper around pack_format.install_pack() — zero new install logic.

    Args:
        template_name: Name of the bundled template (e.g. 'research_assistant')
        target_project: Absolute path to target AgentOS project directory
        force: If True, overwrite existing files

    Returns:
        Result dict from install_pack()

    Raises:
        ValueError: If template not found
        FileNotFoundError: If the .agentpack file hasn't been built yet
    """
    from agentos.packaging.pack_format import install_pack

    tmpl = get_template(template_name)
    if tmpl is None:
        raise ValueError(
            f"Template '{template_name}' not found. "
            f"Available templates: {[t['name'] for t in BUNDLED_TEMPLATES]}"
        )

    pack_path = tmpl["pack_path"]
    if not os.path.exists(pack_path):
        # Try to build it on-demand from source
        try:
            build_template_pack(template_name)
        except Exception as e:
            raise FileNotFoundError(
                f"Template pack '{template_name}.agentpack' not found at {pack_path} "
                f"and could not be built on-demand: {e}. "
                "Run 'python agentos/templates/build_templates.py' to build all template packs."
            ) from e

    result = install_pack(pack_path=pack_path, target_project=target_project, force=force)
    return result


def build_template_pack(template_name: str) -> str:
    """
    Build the .agentpack for a single template from its source YAML files.
    Returns path to the created .agentpack file.
    """
    from agentos.packaging.pack_format import build_pack

    tmpl = get_template(template_name)
    if tmpl is None:
        raise ValueError(f"Template '{template_name}' not found.")

    source_dir = os.path.join(TEMPLATES_SOURCE_DIR, template_name)
    if not os.path.isdir(source_dir):
        raise FileNotFoundError(f"Template source directory not found: {source_dir}")

    os.makedirs(TEMPLATES_DIR, exist_ok=True)
    output_path = os.path.join(TEMPLATES_DIR, f"{template_name}.agentpack")

    build_pack(
        project_path=source_dir,
        include={
            "agents": [a.lower().replace(" ", "_") for a in tmpl["agents"]],
            "tools": [],
            "crews": tmpl["crews"],
        },
        output_path=output_path,
    )
    return output_path


def _pack_path(name: str) -> str:
    return os.path.join(TEMPLATES_DIR, f"{name}.agentpack")
