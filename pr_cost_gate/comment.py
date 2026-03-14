"""PR comment renderer and GitHub poster for pr_cost_gate.

Builds a structured collapsible Markdown summary table from analyzer and
security scan results and posts it to the GitHub PR via the PyGithub API.

Typical usage::

    from github import Github
    from pr_cost_gate.comment import CommentBuilder, CommentPoster
    from pr_cost_gate.analyzer import PRAnalysisResult
    from pr_cost_gate.security import SecurityScanResult
    from pr_cost_gate.config import GateConfig

    config = GateConfig()
    builder = CommentBuilder(config=config)
    body = builder.build(analysis_result, security_result, risk_level="WARN")

    poster = CommentPoster(github_token="ghp_...", config=config)
    comment_url = poster.post(repo="owner/repo", pr_number=42, body=body)
"""

from __future__ import annotations

import textwrap
from dataclasses import dataclass
from typing import Optional

from github import Github
from github.IssueComment import IssueComment

from pr_cost_gate.analyzer import PRAnalysisResult
from pr_cost_gate.config import GateConfig
from pr_cost_gate.security import (
    FindingCategory,
    RiskLevel,
    SecurityFinding,
    SecurityScanResult,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: Comment identity marker embedded in every comment so we can find and update it.
COMMENT_MARKER: str = "<!-- pr-cost-gate-comment -->"

#: Emoji badges for risk levels.
RISK_EMOJI: dict[str, str] = {
    "OK": "✅",
    "WARN": "⚠️",
    "BLOCK": "🚫",
}

#: Short labels for finding categories.
CATEGORY_LABELS: dict[FindingCategory, str] = {
    FindingCategory.SECRET: "🔑 Secret",
    FindingCategory.AUTH_CHANGE: "🔐 Auth Change",
    FindingCategory.SQL_INJECTION: "💉 SQL Injection",
    FindingCategory.DANGEROUS_FUNCTION: "⚡ Dangerous Function",
    FindingCategory.DEPENDENCY_CHANGE: "📦 Dependency Change",
}

#: Short labels for risk level badges inside tables.
RISK_LEVEL_BADGE: dict[RiskLevel, str] = {
    RiskLevel.LOW: "🟢 LOW",
    RiskLevel.MEDIUM: "🟡 MEDIUM",
    RiskLevel.HIGH: "🟠 HIGH",
    RiskLevel.CRITICAL: "🔴 CRITICAL",
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class CommentError(RuntimeError):
    """Raised when posting or updating a PR comment fails."""


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------


@dataclass
class PostedComment:
    """Metadata about a PR comment that was successfully posted or updated.

    Attributes:
        comment_id: The GitHub API comment ID.
        comment_url: The HTML URL of the comment.
        was_updated: ``True`` if an existing comment was updated rather than
            a new one created.
    """

    comment_id: int
    comment_url: str
    was_updated: bool = False


# ---------------------------------------------------------------------------
# Comment builder
# ---------------------------------------------------------------------------


class CommentBuilder:
    """Renders a structured Markdown PR comment from analysis and scan results.

    The comment includes:

    * A header with the overall risk level badge
    * A cost summary section (total tokens, estimated cost, model used)
    * A per-file breakdown table (optionally collapsible)
    * A security findings section (optionally collapsible)
    * Remediation hints for each finding category
    * A footer with the comment marker for future update detection

    Args:
        config: :class:`~pr_cost_gate.config.GateConfig` controlling rendering
            options (collapsible, etc.).
    """

    def __init__(self, config: GateConfig) -> None:
        self._config = config

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def build(
        self,
        analysis: PRAnalysisResult,
        security: SecurityScanResult,
        risk_level: str = "OK",
    ) -> str:
        """Build the full Markdown comment body.

        Args:
            analysis: :class:`~pr_cost_gate.analyzer.PRAnalysisResult` from
                the PR analyzer.
            security: :class:`~pr_cost_gate.security.SecurityScanResult` from
                the security scanner.
            risk_level: Overall risk level string — one of ``'OK'``,
                ``'WARN'``, or ``'BLOCK'``.

        Returns:
            A Markdown-formatted string suitable for posting as a PR comment.
        """
        sections: list[str] = []

        # Identity marker (hidden)
        sections.append(COMMENT_MARKER)

        # Header
        sections.append(self._render_header(analysis, risk_level))

        # Cost summary
        sections.append(self._render_cost_summary(analysis))

        # Per-file breakdown
        if analysis.files or analysis.skipped_files:
            sections.append(self._render_file_breakdown(analysis))

        # Security findings
        if security.findings:
            sections.append(self._render_security_findings(security))
        else:
            sections.append(self._render_no_security_findings(security))

        # Footer
        sections.append(self._render_footer())

        return "\n\n".join(sections)

    def should_post(
        self,
        risk_level: str,
    ) -> bool:
        """Return ``True`` if a comment should be posted given *risk_level*.

        The decision is based on ``config.comment.post`` and
        ``config.comment.post_when``.

        Args:
            risk_level: One of ``'OK'``, ``'WARN'``, or ``'BLOCK'``.

        Returns:
            ``True`` when a comment should be posted.
        """
        if not self._config.comment.post:
            return False

        post_when = self._config.comment.post_when
        if post_when == "always":
            return True
        if post_when == "warn":
            return risk_level in ("WARN", "BLOCK")
        if post_when == "block":
            return risk_level == "BLOCK"
        # Fallback
        return True

    # ------------------------------------------------------------------
    # Section renderers
    # ------------------------------------------------------------------

    def _render_header(self, analysis: PRAnalysisResult, risk_level: str) -> str:
        """Render the comment header with PR title and risk badge."""
        emoji = RISK_EMOJI.get(risk_level, "ℹ️")
        risk_label = f"{emoji} **{risk_level}**"

        title_part = f" — *{analysis.pr_title}*" if analysis.pr_title else ""
        model_part = analysis.model

        lines = [
            f"## 🤖 PR Cost Gate{title_part}",
            "",
            f"| Field | Value |",
            f"|-------|-------|",
            f"| **Risk Level** | {risk_label} |",
            f"| **Model** | `{model_part}` |",
            f"| **PR** | [#{analysis.pr_number}]({analysis.pr_url}) |",
            f"| **Branch** | `{analysis.head_branch}` → `{analysis.base_branch}` |",
        ]
        return "\n".join(lines)

    def _render_cost_summary(self, analysis: PRAnalysisResult) -> str:
        """Render the cost estimation summary table."""
        capped_note = " *(some files capped)*" if analysis.any_capped else ""
        lines = [
            "### 💰 Cost Estimation",
            "",
            "| Metric | Value |",
            "|--------|-------|",
            f"| **Total Input Tokens** | `{analysis.input_tokens:,}`{capped_note} |",
            f"| **Estimated Output Tokens** | `{analysis.output_tokens:,}` |",
            f"| **Total Tokens** | `{analysis.total_tokens:,}` |",
            f"| **Estimated Cost** | `${analysis.estimated_cost_usd:.4f} USD` |",
            f"| **Files Analysed** | `{len(analysis.files)}` |",
            f"| **Files Skipped** | `{len(analysis.skipped_files)}` |",
        ]
        return "\n".join(lines)

    def _render_file_breakdown(self, analysis: PRAnalysisResult) -> str:
        """Render a per-file token and cost breakdown table."""
        if not analysis.files:
            header = "### 📂 File Breakdown\n\n*No files were analysed.*"
            return header

        table_rows: list[str] = [
            "| File | Status | Tokens | Cost (USD) | Capped |",
            "|------|--------|-------:|----------:|:------:|",
        ]
        # Sort by token count descending so the most expensive files are first
        sorted_files = sorted(analysis.files, key=lambda f: f.token_count, reverse=True)
        for fa in sorted_files:
            capped_indicator = "⚠️" if fa.was_capped else ""
            filename_display = self._truncate_filename(fa.filename, max_length=60)
            row = (
                f"| `{filename_display}` "
                f"| {fa.status} "
                f"| {fa.token_count:,} "
                f"| ${fa.estimated_cost_usd:.4f} "
                f"| {capped_indicator} |"
            )
            table_rows.append(row)

        # Total row
        table_rows.append(
            f"| **Total** | | **{analysis.total_tokens:,}** "
            f"| **${analysis.estimated_cost_usd:.4f}** | |"
        )

        table_content = "\n".join(table_rows)

        # Skipped files note
        skipped_note = ""
        if analysis.skipped_files:
            skipped_list = ", ".join(f"`{p}`" for p in analysis.skipped_files[:10])
            extra = ""
            if len(analysis.skipped_files) > 10:
                extra = f" and {len(analysis.skipped_files) - 10} more"
            skipped_note = f"\n\n> **Skipped files** ({len(analysis.skipped_files)}): {skipped_list}{extra}"

        section_title = "### 📂 File Breakdown"

        if self._config.comment.collapsible:
            inner = f"{table_content}{skipped_note}"
            return (
                f"{section_title}\n\n"
                f"<details>\n"
                f"<summary>Click to expand per-file breakdown ({len(analysis.files)} files)</summary>\n\n"
                f"{inner}\n\n"
                f"</details>"
            )
        else:
            return f"{section_title}\n\n{table_content}{skipped_note}"

    def _render_security_findings(
        self, security: SecurityScanResult
    ) -> str:
        """Render the security findings section."""
        total = security.total_count
        highest = security.highest_risk_level
        highest_label = RISK_LEVEL_BADGE.get(highest, str(highest)) if highest else "N/A"

        summary_lines = [
            "### 🔒 Security Findings",
            "",
            f"**{total} finding(s) detected** — Highest severity: {highest_label}",
            "",
        ]

        # Category summary
        by_cat = security.by_category
        if by_cat:
            cat_lines = ["| Category | Count |", "|----------|------:|"]  
            for cat, findings_list in sorted(by_cat.items(), key=lambda x: x[0].value):
                label = CATEGORY_LABELS.get(cat, cat.value)
                cat_lines.append(f"| {label} | {len(findings_list)} |")
            summary_lines.extend(cat_lines)
            summary_lines.append("")

        # Findings detail table
        detail_rows = [
            "| # | Rule | File | Risk | Description | Line |",
            "|---|------|------|------|-------------|-----:|",
        ]
        for idx, finding in enumerate(security.findings, start=1):
            risk_badge = RISK_LEVEL_BADGE.get(finding.risk_level, finding.risk_level.value)
            filename_display = self._truncate_filename(finding.filename, max_length=40)
            sanitised = finding.sanitised_line(max_length=80)
            # Escape pipe characters in content to avoid breaking the table
            sanitised_escaped = sanitised.replace("|", "\\|")
            description_escaped = finding.description.replace("|", "\\|")
            line_ref = str(finding.line_number) if finding.line_number > 0 else "—"
            detail_rows.append(
                f"| {idx} "
                f"| `{finding.rule_id}` "
                f"| `{filename_display}` "
                f"| {risk_badge} "
                f"| {description_escaped} "
                f"| {line_ref} |"
            )

        detail_content = "\n".join(summary_lines) + "\n".join(detail_rows)

        # Remediation hints — deduplicated by rule_id
        remediation_parts = self._render_remediation_hints(security.findings)

        full_content = detail_content
        if remediation_parts:
            full_content += f"\n\n{remediation_parts}"

        if self._config.comment.collapsible:
            return (
                "### 🔒 Security Findings\n\n"
                f"**{total} finding(s) detected** — Highest severity: {highest_label}\n\n"
                "<details>\n"
                f"<summary>Click to expand security findings ({total} issues)</summary>\n\n"
                + "\n".join(cat_lines if by_cat else [])
                + "\n\n"
                + "\n".join(detail_rows)
                + (f"\n\n{remediation_parts}" if remediation_parts else "")
                + "\n\n</details>"
            )
        else:
            return full_content

    def _render_no_security_findings(self, security: SecurityScanResult) -> str:
        """Render a clean bill of health when no security findings exist."""
        scanned_count = len(security.scanned_files)
        skipped_count = len(security.skipped_files)
        lines = [
            "### 🔒 Security Findings",
            "",
            f"✅ **No security issues detected** across {scanned_count} scanned file(s).",
        ]
        if skipped_count:
            lines.append(
                f"\n> {skipped_count} file(s) were skipped (binary or no patch available)."
            )
        return "\n".join(lines)

    def _render_remediation_hints(
        self, findings: list[SecurityFinding]
    ) -> str:
        """Render a deduplicated list of remediation hints."""
        seen_rule_ids: set[str] = set()
        hints: list[str] = []

        for finding in findings:
            if finding.rule_id not in seen_rule_ids and finding.remediation:
                seen_rule_ids.add(finding.rule_id)
                hints.append(
                    f"- **`{finding.rule_id}`**: {finding.remediation}"
                )

        if not hints:
            return ""

        return "**Remediation Hints:**\n" + "\n".join(hints)

    def _render_footer(self) -> str:
        """Render the comment footer."""
        return textwrap.dedent("""\
            ---
            <sub>Generated by [pr-cost-gate](https://github.com/your-org/pr_cost_gate). \
Token counts are estimates; actual AI review costs may vary.</sub>
        """).strip()

    @staticmethod
    def _truncate_filename(filename: str, max_length: int = 60) -> str:
        """Truncate a filename to *max_length* characters, preserving the end.

        For long paths, the beginning is replaced with ``…`` so the filename
        extension and final path components remain visible.

        Args:
            filename: File path string.
            max_length: Maximum characters to return.

        Returns:
            Possibly-truncated filename string.
        """
        if len(filename) <= max_length:
            return filename
        return "…" + filename[-(max_length - 1):]


# ---------------------------------------------------------------------------
# Determine overall risk level
# ---------------------------------------------------------------------------


def determine_risk_level(
    analysis: PRAnalysisResult,
    security: SecurityScanResult,
    config: GateConfig,
) -> str:
    """Determine the overall risk level for the PR.

    The risk level is determined by comparing the estimated cost against the
    configured thresholds and whether any critical or high security findings
    were detected.

    Decision order (highest precedence first):

    1. ``BLOCK`` — estimated cost exceeds ``block_usd`` threshold
       *or* security has CRITICAL findings and ``block_usd > 0``
    2. ``WARN`` — estimated cost exceeds ``warn_usd`` threshold
       *or* security has HIGH+ findings
    3. ``OK`` — no thresholds exceeded

    Args:
        analysis: The PR analysis result.
        security: The security scan result.
        config: Configuration with cost thresholds.

    Returns:
        One of ``'OK'``, ``'WARN'``, or ``'BLOCK'``.
    """
    cost = analysis.estimated_cost_usd
    block_usd = config.thresholds.block_usd
    warn_usd = config.thresholds.warn_usd

    # BLOCK conditions
    if block_usd > 0 and cost >= block_usd:
        return "BLOCK"
    if block_usd > 0 and security.has_critical:
        return "BLOCK"

    # WARN conditions
    if warn_usd > 0 and cost >= warn_usd:
        return "WARN"
    if security.has_high:
        return "WARN"

    return "OK"


# ---------------------------------------------------------------------------
# Comment poster
# ---------------------------------------------------------------------------


class CommentPoster:
    """Posts or updates the PR cost gate comment on a GitHub pull request.

    Uses the PyGithub library to interact with the GitHub API.  When a
    previous comment from this tool already exists on the PR (identified by
    :data:`COMMENT_MARKER`), it is updated in-place rather than a new comment
    being created.

    Args:
        github_token: GitHub personal access token or ``GITHUB_TOKEN``.
        config: :class:`~pr_cost_gate.config.GateConfig` (used for logging
            and future configuration of the poster behaviour).
    """

    def __init__(self, github_token: str, config: GateConfig) -> None:
        self._token = github_token
        self._config = config
        self._gh: Optional[Github] = None

    @property
    def gh(self) -> Github:
        """Lazily-initialised :class:`github.Github` client."""
        if self._gh is None:
            self._gh = Github(self._token)
        return self._gh

    def post(
        self,
        repo: str,
        pr_number: int,
        body: str,
    ) -> PostedComment:
        """Post or update the cost gate comment on the specified PR.

        If a previous cost gate comment is found (by searching for
        :data:`COMMENT_MARKER`), it is edited in-place.  Otherwise a new
        comment is created.

        Args:
            repo: Repository in ``owner/name`` format.
            pr_number: Pull request number.
            body: Full Markdown comment body to post.

        Returns:
            A :class:`PostedComment` with the comment ID and URL.

        Raises:
            CommentError: If the GitHub API call fails.
        """
        try:
            gh_repo = self.gh.get_repo(repo)
        except Exception as exc:
            raise CommentError(
                f"Cannot access repository {repo!r}: {exc}"
            ) from exc

        try:
            issue = gh_repo.get_issue(pr_number)
        except Exception as exc:
            raise CommentError(
                f"Cannot access PR #{pr_number} in {repo!r}: {exc}"
            ) from exc

        # Search for an existing comment from this tool
        existing: Optional[IssueComment] = None
        try:
            for comment in issue.get_comments():
                if COMMENT_MARKER in (comment.body or ""):
                    existing = comment
                    break
        except Exception as exc:
            raise CommentError(
                f"Cannot list comments on PR #{pr_number} in {repo!r}: {exc}"
            ) from exc

        if existing is not None:
            # Update the existing comment
            try:
                existing.edit(body)
            except Exception as exc:
                raise CommentError(
                    f"Cannot update comment {existing.id} on PR #{pr_number}: {exc}"
                ) from exc
            return PostedComment(
                comment_id=existing.id,
                comment_url=existing.html_url,
                was_updated=True,
            )
        else:
            # Create a new comment
            try:
                new_comment = issue.create_comment(body)
            except Exception as exc:
                raise CommentError(
                    f"Cannot create comment on PR #{pr_number} in {repo!r}: {exc}"
                ) from exc
            return PostedComment(
                comment_id=new_comment.id,
                comment_url=new_comment.html_url,
                was_updated=False,
            )


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------


def build_and_post_comment(
    github_token: str,
    repo: str,
    pr_number: int,
    analysis: PRAnalysisResult,
    security: SecurityScanResult,
    config: Optional[GateConfig] = None,
) -> tuple[str, Optional[PostedComment]]:
    """High-level convenience wrapper: build a comment and optionally post it.

    Determines the risk level, builds the Markdown comment body, and — if
    ``config.comment.post`` is ``True`` and the risk level meets the
    ``post_when`` threshold — posts it to GitHub.

    Args:
        github_token: GitHub personal access token.
        repo: Repository in ``owner/name`` format.
        pr_number: Pull request number.
        analysis: PR analysis result from :class:`~pr_cost_gate.analyzer.PRAnalyzer`.
        security: Security scan result from :class:`~pr_cost_gate.security.SecurityScanner`.
        config: Configuration to use.  Defaults to all defaults when ``None``.

    Returns:
        A tuple ``(risk_level, posted_comment)`` where *posted_comment* is
        ``None`` when the comment was not posted (due to config settings).

    Raises:
        CommentError: If posting fails.
    """
    if config is None:
        config = GateConfig()

    risk_level = determine_risk_level(analysis, security, config)
    builder = CommentBuilder(config=config)
    body = builder.build(analysis, security, risk_level)

    posted: Optional[PostedComment] = None
    if builder.should_post(risk_level):
        poster = CommentPoster(github_token=github_token, config=config)
        posted = poster.post(repo=repo, pr_number=pr_number, body=body)

    return risk_level, posted
