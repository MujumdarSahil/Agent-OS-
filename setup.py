"""
Setup script for AgentOS
"""

from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

# Runtime dependencies are declared in pyproject.toml ([project].dependencies);
# setuptools ignores install_requires here whenever a [project] table exists.

version_vars = {}
with open("agentos/__version__.py", "r", encoding="utf-8") as f:
    exec(f.read(), version_vars)

setup(
    name="agentos",
    version=version_vars["__version__"],
    author="AgentOS Team",
    description="A production-grade multi-agent framework",
    long_description=long_description,
    long_description_content_type="text/markdown",
    package_dir={"": ".", "agentos_swe": "SWE/agentos_swe"},
    packages=find_packages() + ["agentos_swe"] + [f"agentos_swe.{p}" for p in find_packages(where="SWE/agentos_swe")],
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Topic :: Software Development :: Libraries :: Python Modules",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
    ],
    python_requires=">=3.11",
    entry_points={
        "console_scripts": [
            "agentos=agentos.app:main",
        ],
    },
)

