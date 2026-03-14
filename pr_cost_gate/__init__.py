"""pr_cost_gate: Analyze GitHub PR diffs for AI review costs and security risks.

This package provides:
- Token-accurate cost estimation per AI model (GPT-4o, Claude 3.5 Sonnet, Claude 3 Opus)
- Security risk pattern scanning for secrets, auth changes, SQL injection, and more
- Configurable cost thresholds that emit warnings or block CI workflows
- Automatic GitHub PR comment posting with a structured Markdown summary

Typical usage::

    from pr_cost_gate.analyzer import PRAnalyzer
    from pr_cost_gate.security import SecurityScanner
    from pr_cost_gate.comment import CommentPoster
    from pr_cost_gate.config import load_config
"""

from __future__ import annotations

__version__ = "0.1.0"
__author__ = "pr_cost_gate contributors"
__license__ = "MIT"

__all__ = [
    "__version__",
    "__author__",
    "__license__",
]
