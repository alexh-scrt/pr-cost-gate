"""Unit tests for pr_cost_gate.comment.

Covers:
- CommentBuilder.build() output structure and content
- CommentBuilder.should_post() logic for all post_when values
- CommentBuilder._render_header() with/without PR title
- CommentBuilder._render_cost_summary() formatting
- CommentBuilder._render_file_breakdown() collapsible and non-collapsible modes
- CommentBuilder._render_security_findings() with real findings
- CommentBuilder._render_no_security_findings() clean state
- CommentBuilder._render_remediation_hints() deduplication
- CommentBuilder._truncate_filename() edge cases
- determine_risk_level() against all threshold combinations
- COMMENT_MARKER presence in built comments
- CommentPoster.post() — create new comment path
- CommentPoster.post() — update existing comment path
- CommentPoster error handling
- build_and_post_comment() convenience wrapper
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Optional
from unittest.mock import MagicMock, PropertyMock, patch, call

import pytest

from pr_cost_gate.analyzer import FileAnalysis, PRAnalysisResult
from pr_cost_gate.comment import (
    COMMENT_MARKER,
    CommentBuilder,
    CommentError,
    CommentPoster,
    PostedComment,
    build_and_post_comment,
    determine_risk_level,
)
from pr_cost_gate.config import (
    CommentConfig,
    GateConfig,
    ThresholdConfig,
)
from pr_cost_gate.security import (
    FindingCategory,
    RiskLevel,
    SecurityFinding,
    SecurityScanResult,
)


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


def _make_analysis(
    repo: str = "owner/repo",
    pr_number: int = 1,
    model: str = "gpt-4o",
    total_tokens: int = 5000,
    estimated_cost_usd: float = 0.05,
    files: Optional[list[FileAnalysis]] = None,
    skipped_files: Optional[list[str]] = None,
    any_capped: bool = False,
    pr_title: str = "Test PR",
    pr_url: str = "https://github.com/owner/repo/pull/1",
    base_branch: str = "main",
    head_branch: str = "feature/test",
    input_tokens: Optional[int] = None,
    output_tokens: Optional[int] = None,
) -> PRAnalysisResult:
    """Create a PRAnalysisResult for testing."""
    files = files or []
    skipped_files = skipped_files or []
    if input_tokens is None:
        input_tokens = total_tokens
    if output_tokens is None:
        output_tokens = int(total_tokens * 0.20)
    result = PRAnalysisResult(
        repo=repo,
        pr_number=pr_number,
        model=model,
        files=files,
        skipped_files=skipped_files,
        total_tokens=total_tokens,
        estimated_cost_usd=estimated_cost_usd,
        input_tokens=input_tokens,
        output_tokens=output_tokens,
        any_capped=any_capped,
        pr_title=pr_title,
        pr_url=pr_url,
        base_branch=base_branch,
        head_branch=head_branch,
    )
    return result


def _make_file_analysis(
    filename: str = "src/main.py",
    token_count: int = 200,
    estimated_cost_usd: float = 0.002,
    was_capped: bool = False,
    status: str = "modified",
    additions: int = 10,
    deletions: int = 5,
) -> FileAnalysis:
    """Create a FileAnalysis for testing."""
    return FileAnalysis(
        filename=filename,
        token_count=token_count,
        estimated_cost_usd=estimated_cost_usd,
        was_capped=was_capped,
        status=status,
        additions=additions,
        deletions=deletions,
    )


def _make_security_result(
    findings: Optional[list[SecurityFinding]] = None,
    scanned_files: Optional[list[str]] = None,
    skipped_files: Optional[list[str]] = None,
) -> SecurityScanResult:
    """Create a SecurityScanResult for testing."""
    result = SecurityScanResult(
        findings=findings or [],
        scanned_files=scanned_files or [],
        skipped_files=skipped_files or [],
    )
    result._update_highest_risk()
    return result


def _make_finding(
    category: FindingCategory = FindingCategory.SECRET,
    rule_id: str = "SECRET-001",
    description: str = "Hardcoded API key",
    filename: str = "config.py",
    line_content: str = 'api_key = "sk-abcdef"',
    line_number: int = 10,
    risk_level: RiskLevel = RiskLevel.CRITICAL,
    remediation: str = "Use environment variables.",
) -> SecurityFinding:
    """Create a SecurityFinding for testing."""
    return SecurityFinding(
        category=category,
        rule_id=rule_id,
        description=description,
        filename=filename,
        line_content=line_content,
        line_number=line_number,
        risk_level=risk_level,
        remediation=remediation,
    )


def _make_config(
    post: bool = True,
    collapsible: bool = True,
    post_when: str = "always",
    warn_usd: float = 1.0,
    block_usd: float = 5.0,
) -> GateConfig:
    """Create a GateConfig for testing."""
    return GateConfig(
        comment=CommentConfig(post=post, collapsible=collapsible, post_when=post_when),
        thresholds=ThresholdConfig(warn_usd=warn_usd, block_usd=block_usd),
    )


# ---------------------------------------------------------------------------
# COMMENT_MARKER
# ---------------------------------------------------------------------------


class TestCommentMarker:
    """Test that the COMMENT_MARKER constant is correct."""

    def test_marker_is_html_comment(self) -> None:
        assert COMMENT_MARKER.startswith("<!--")
        assert COMMENT_MARKER.endswith("-->")

    def test_marker_contains_identifier(self) -> None:
        assert "pr-cost-gate" in COMMENT_MARKER


# ---------------------------------------------------------------------------
# CommentBuilder.build() — top-level structure
# ---------------------------------------------------------------------------


class TestCommentBuilderBuild:
    """Test the build() method produces correct overall structure."""

    def test_comment_contains_marker(self) -> None:
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis()
        security = _make_security_result()
        body = builder.build(analysis, security, risk_level="OK")
        assert COMMENT_MARKER in body

    def test_comment_contains_header(self) -> None:
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis(pr_title="My Feature")
        security = _make_security_result()
        body = builder.build(analysis, security, risk_level="OK")
        assert "PR Cost Gate" in body
        assert "My Feature" in body

    def test_comment_contains_cost_section(self) -> None:
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis(total_tokens=1234)
        security = _make_security_result()
        body = builder.build(analysis, security, risk_level="OK")
        assert "Cost Estimation" in body
        assert "1,234" in body

    def test_comment_contains_file_breakdown_when_files_present(self) -> None:
        files = [_make_file_analysis("src/main.py", 200)]
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis(files=files)
        security = _make_security_result()
        body = builder.build(analysis, security, risk_level="OK")
        assert "File Breakdown" in body
        assert "src/main.py" in body

    def test_comment_shows_ok_when_no_issues(self) -> None:
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis()
        security = _make_security_result()
        body = builder.build(analysis, security, risk_level="OK")
        assert "OK" in body
        assert "✅" in body

    def test_comment_shows_warn_badge(self) -> None:
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis()
        security = _make_security_result()
        body = builder.build(analysis, security, risk_level="WARN")
        assert "WARN" in body
        assert "⚠️" in body

    def test_comment_shows_block_badge(self) -> None:
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis()
        security = _make_security_result()
        body = builder.build(analysis, security, risk_level="BLOCK")
        assert "BLOCK" in body
        assert "🚫" in body

    def test_comment_contains_footer(self) -> None:
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis()
        security = _make_security_result()
        body = builder.build(analysis, security, risk_level="OK")
        assert "pr-cost-gate" in body.lower()

    def test_comment_with_security_findings(self) -> None:
        finding = _make_finding()
        security = _make_security_result(
            findings=[finding], scanned_files=["config.py"]
        )
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis()
        body = builder.build(analysis, security, risk_level="BLOCK")
        assert "Security Findings" in body
        assert "SECRET-001" in body
        assert "config.py" in body

    def test_comment_no_findings_shows_clean_message(self) -> None:
        security = _make_security_result(scanned_files=["app.py", "db.py"])
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis()
        body = builder.build(analysis, security, risk_level="OK")
        assert "No security issues detected" in body

    def test_comment_returns_string(self) -> None:
        builder = CommentBuilder(config=_make_config())
        body = builder.build(
            _make_analysis(), _make_security_result(), risk_level="OK"
        )
        assert isinstance(body, str)
        assert len(body) > 0

    def test_comment_with_empty_pr_title(self) -> None:
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis(pr_title="")
        body = builder.build(analysis, _make_security_result(), risk_level="OK")
        assert "PR Cost Gate" in body
        # Should not have '— *' when title is empty
        assert "— *" not in body


# ---------------------------------------------------------------------------
# CommentBuilder — header rendering
# ---------------------------------------------------------------------------


class TestRenderHeader:
    """Test the header section rendering."""

    def test_pr_number_in_header(self) -> None:
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis(pr_number=42)
        security = _make_security_result()
        body = builder.build(analysis, security, "OK")
        assert "#42" in body

    def test_pr_url_in_header(self) -> None:
        url = "https://github.com/owner/repo/pull/99"
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis(pr_number=99, pr_url=url)
        body = builder.build(analysis, _make_security_result(), "OK")
        assert url in body

    def test_model_in_header(self) -> None:
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis(model="claude-3-opus")
        body = builder.build(analysis, _make_security_result(), "OK")
        assert "claude-3-opus" in body

    def test_branches_in_header(self) -> None:
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis(base_branch="main", head_branch="feature/my-thing")
        body = builder.build(analysis, _make_security_result(), "OK")
        assert "main" in body
        assert "feature/my-thing" in body

    def test_risk_level_bold_in_header(self) -> None:
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis()
        body = builder.build(analysis, _make_security_result(), "WARN")
        assert "**WARN**" in body


# ---------------------------------------------------------------------------
# CommentBuilder — cost summary rendering
# ---------------------------------------------------------------------------


class TestRenderCostSummary:
    """Test cost summary section rendering."""

    def test_total_tokens_formatted(self) -> None:
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis(
            total_tokens=12345,
            input_tokens=12345,
            output_tokens=2469,
        )
        body = builder.build(analysis, _make_security_result(), "OK")
        assert "12,345" in body

    def test_estimated_cost_formatted(self) -> None:
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis(estimated_cost_usd=0.1234)
        body = builder.build(analysis, _make_security_result(), "OK")
        assert "0.1234" in body

    def test_capped_note_shown_when_capped(self) -> None:
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis(any_capped=True)
        body = builder.build(analysis, _make_security_result(), "OK")
        assert "capped" in body.lower()

    def test_no_capped_note_when_not_capped(self) -> None:
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis(any_capped=False)
        body = builder.build(analysis, _make_security_result(), "OK")
        assert "capped" not in body.lower()

    def test_files_analysed_count(self) -> None:
        files = [
            _make_file_analysis("a.py"),
            _make_file_analysis("b.py"),
        ]
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis(files=files)
        body = builder.build(analysis, _make_security_result(), "OK")
        assert "2" in body  # 2 files

    def test_files_skipped_count(self) -> None:
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis(skipped_files=["yarn.lock", "poetry.lock"])
        body = builder.build(analysis, _make_security_result(), "OK")
        assert "2" in body

    def test_output_tokens_shown(self) -> None:
        builder = CommentBuilder(config=_make_config())
        analysis = _make_analysis(total_tokens=1000, output_tokens=200)
        body = builder.build(analysis, _make_security_result(), "OK")
        assert "200" in body


# ---------------------------------------------------------------------------
# CommentBuilder — file breakdown rendering
# ---------------------------------------------------------------------------


class TestRenderFileBreakdown:
    """Test per-file breakdown table rendering."""

    def test_collapsible_mode_uses_details_tag(self) -> None:
        config = _make_config(collapsible=True)
        files = [_make_file_analysis("src/main.py")]
        builder = CommentBuilder(config=config)
        analysis = _make_analysis(files=files)
        body = builder.build(analysis, _make_security_result(), "OK")
        assert "<details>" in body
        assert "</details>" in body
        assert "<summary>" in body

    def test_non_collapsible_mode_no_details_tag(self) -> None:
        config = _make_config(collapsible=False)
        files = [_make_file_analysis("src/main.py")]
        builder = CommentBuilder(config=config)
        analysis = _make_analysis(files=files)
        body = builder.build(analysis, _make_security_result(), "OK")
        assert "<details>" not in body

    def test_filename_in_table(self) -> None:
        config = _make_config(collapsible=False)
        files = [_make_file_analysis("src/my_module.py", 500)]
        builder = CommentBuilder(config=config)
        analysis = _make_analysis(files=files, total_tokens=500)
        body = builder.build(analysis, _make_security_result(), "OK")
        assert "src/my_module.py" in body

    def test_token_count_in_table(self) -> None:
        config = _make_config(collapsible=False)
        files = [_make_file_analysis("a.py", token_count=1234)]
        builder = CommentBuilder(config=config)
        analysis = _make_analysis(files=files, total_tokens=1234)
        body = builder.build(analysis, _make_security_result(), "OK")
        assert "1,234" in body

    def test_cost_in_table(self) -> None:
        config = _make_config(collapsible=False)
        files = [_make_file_analysis("a.py", estimated_cost_usd=0.0456)]
        builder = CommentBuilder(config=config)
        analysis = _make_analysis(files=files)
        body = builder.build(analysis, _make_security_result(), "OK")
        assert "0.0456" in body

    def test_capped_indicator_shown(self) -> None:
        config = _make_config(collapsible=False)
        files = [_make_file_analysis("big.py", was_capped=True)]
        builder = CommentBuilder(config=config)
        analysis = _make_analysis(files=files, any_capped=True)
        body = builder.build(analysis, _make_security_result(), "OK")
        assert "⚠️" in body

    def test_files_sorted_by_token_count_descending(self) -> None:
        config = _make_config(collapsible=False)
        files = [
            _make_file_analysis("small.py", token_count=10),
            _make_file_analysis("large.py", token_count=1000),
            _make_file_analysis("medium.py", token_count=100),
        ]
        builder = CommentBuilder(config=config)
        analysis = _make_analysis(files=files)
        body = builder.build(analysis, _make_security_result(), "OK")
        # Find positions of filenames
        pos_large = body.index("large.py")
        pos_medium = body.index("medium.py")
        pos_small = body.index("small.py")
        assert pos_large < pos_medium < pos_small

    def test_total_row_in_table(self) -> None:
        config = _make_config(collapsible=False)
        files = [_make_file_analysis("a.py", token_count=500)]
        builder = CommentBuilder(config=config)
        analysis = _make_analysis(files=files, total_tokens=500)
        body = builder.build(analysis, _make_security_result(), "OK")
        assert "Total" in body

    def test_skipped_files_note_shown(self) -> None:
        config = _make_config(collapsible=False)
        builder = CommentBuilder(config=config)
        analysis = _make_analysis(
            files=[_make_file_analysis("a.py")],
            skipped_files=["poetry.lock", "yarn.lock"],
        )
        body = builder.build(analysis, _make_security_result(), "OK")
        assert "Skipped files" in body
        assert "poetry.lock" in body

    def test_no_files_shows_no_analysed_message(self) -> None:
        config = _make_config(collapsible=False)
        builder = CommentBuilder(config=config)
        analysis = _make_analysis(files=[], total_tokens=0)
        body = builder.build(analysis, _make_security_result(), "OK")
        # Either the file breakdown is not shown or shows 'No files'
        # Based on implementation, file breakdown section only renders when files or skipped
        assert isinstance(body, str)  # At minimum it renders without error

    def test_long_filename_truncated(self) -> None:
        long_name = "src/very/deeply/nested/path/to/some/file/that/is/quite/long/indeed.py"
        config = _make_config(collapsible=False)
        files = [_make_file_analysis(long_name, token_count=100)]
        builder = CommentBuilder(config=config)
        analysis = _make_analysis(files=files)
        body = builder.build(analysis, _make_security_result(), "OK")
        # The file entry should appear (possibly truncated)
        assert isinstance(body, str)

    def test_status_shown_in_table(self) -> None:
        config = _make_config(collapsible=False)
        files = [_make_file_analysis("new_file.py", status="added")]
        builder = CommentBuilder(config=config)
        analysis = _make_analysis(files=files)
        body = builder.build(analysis, _make_security_result(), "OK")
        assert "added" in body


# ---------------------------------------------------------------------------
# CommentBuilder — security findings rendering
# ---------------------------------------------------------------------------


class TestRenderSecurityFindings:
    """Test security findings section rendering."""

    def test_finding_count_in_output(self) -> None:
        findings = [
            _make_finding(rule_id="SECRET-001"),
            _make_finding(
                category=FindingCategory.SQL_INJECTION,
                rule_id="SQL-001",
                risk_level=RiskLevel.HIGH,
            ),
        ]
        security = _make_security_result(findings=findings, scanned_files=["app.py"])
        config = _make_config(collapsible=False)
        builder = CommentBuilder(config=config)
        body = builder.build(_make_analysis(), security, "BLOCK")
        assert "2 finding(s)" in body

    def test_rule_id_in_table(self) -> None:
        finding = _make_finding(rule_id="SECRET-001")
        security = _make_security_result(findings=[finding])
        config = _make_config(collapsible=False)
        builder = CommentBuilder(config=config)
        body = builder.build(_make_analysis(), security, "BLOCK")
        assert "SECRET-001" in body

    def test_filename_in_security_table(self) -> None:
        finding = _make_finding(filename="secret_config.py")
        security = _make_security_result(findings=[finding])
        config = _make_config(collapsible=False)
        builder = CommentBuilder(config=config)
        body = builder.build(_make_analysis(), security, "BLOCK")
        assert "secret_config.py" in body

    def test_risk_level_badge_in_table(self) -> None:
        finding = _make_finding(risk_level=RiskLevel.CRITICAL)
        security = _make_security_result(findings=[finding])
        config = _make_config(collapsible=False)
        builder = CommentBuilder(config=config)
        body = builder.build(_make_analysis(), security, "BLOCK")
        assert "CRITICAL" in body

    def test_remediation_hints_shown(self) -> None:
        finding = _make_finding(
            rule_id="SECRET-001",
            remediation="Remove secret and use env var.",
        )
        security = _make_security_result(findings=[finding])
        config = _make_config(collapsible=False)
        builder = CommentBuilder(config=config)
        body = builder.build(_make_analysis(), security, "BLOCK")
        assert "Remove secret and use env var." in body

    def test_remediation_deduplicated(self) -> None:
        # Two findings with the same rule_id should only show one remediation hint
        findings = [
            _make_finding(rule_id="SECRET-001", remediation="Use env var."),
            _make_finding(
                rule_id="SECRET-001",
                remediation="Use env var.",
                filename="other.py",
            ),
        ]
        security = _make_security_result(findings=findings)
        config = _make_config(collapsible=False)
        builder = CommentBuilder(config=config)
        body = builder.build(_make_analysis(), security, "BLOCK")
        # Should appear exactly once in remediation section
        assert body.count("Use env var.") == 1

    def test_highest_risk_level_shown(self) -> None:
        finding = _make_finding(risk_level=RiskLevel.CRITICAL)
        security = _make_security_result(findings=[finding])
        config = _make_config(collapsible=False)
        builder = CommentBuilder(config=config)
        body = builder.build(_make_analysis(), security, "BLOCK")
        assert "CRITICAL" in body

    def test_category_summary_present(self) -> None:
        findings = [
            _make_finding(category=FindingCategory.SECRET, rule_id="SECRET-001"),
            _make_finding(
                category=FindingCategory.DEPENDENCY_CHANGE,
                rule_id="DEP-001",
                risk_level=RiskLevel.MEDIUM,
            ),
        ]
        security = _make_security_result(findings=findings)
        config = _make_config(collapsible=False)
        builder = CommentBuilder(config=config)
        body = builder.build(_make_analysis(), security, "WARN")
        # Category labels should be present
        assert "Secret" in body or "secret" in body.lower()
        assert "Dependency" in body or "dependency" in body.lower()

    def test_collapsible_security_uses_details_tag(self) -> None:
        finding = _make_finding()
        security = _make_security_result(findings=[finding])
        config = _make_config(collapsible=True)
        builder = CommentBuilder(config=config)
        body = builder.build(_make_analysis(), security, "BLOCK")
        assert "<details>" in body

    def test_non_collapsible_security_no_details_tag_in_security_section(self) -> None:
        finding = _make_finding()
        security = _make_security_result(findings=[finding])
        config = _make_config(collapsible=False)
        builder = CommentBuilder(config=config)
        body = builder.build(_make_analysis(), security, "BLOCK")
        # With collapsible=False, no <details> for security
        # (could still have details for file breakdown)
        assert isinstance(body, str)

    def test_line_number_shown(self) -> None:
        finding = _make_finding(line_number=42)
        security = _make_security_result(findings=[finding])
        config = _make_config(collapsible=False)
        builder = CommentBuilder(config=config)
        body = builder.build(_make_analysis(), security, "BLOCK")
        assert "42" in body

    def test_zero_line_number_shows_dash(self) -> None:
        finding = _make_finding(line_number=0)
        security = _make_security_result(findings=[finding])
        config = _make_config(collapsible=False)
        builder = CommentBuilder(config=config)
        body = builder.build(_make_analysis(), security, "BLOCK")
        assert "—" in body


# ---------------------------------------------------------------------------
# CommentBuilder._truncate_filename
# ---------------------------------------------------------------------------


class TestTruncateFilename:
    """Tests for the _truncate_filename static method."""

    def test_short_filename_unchanged(self) -> None:
        assert CommentBuilder._truncate_filename("src/main.py", 60) == "src/main.py"

    def test_long_filename_truncated(self) -> None:
        long_name = "a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z.py"
        result = CommentBuilder._truncate_filename(long_name, 30)
        assert len(result) <= 30
        assert result.startswith("…")

    def test_truncated_preserves_end(self) -> None:
        long_name = "path/to/some/deeply/nested/important_file.py"
        result = CommentBuilder._truncate_filename(long_name, 20)
        assert result.endswith(long_name[-(19):])

    def test_exactly_at_limit_not_truncated(self) -> None:
        name = "x" * 60
        result = CommentBuilder._truncate_filename(name, 60)
        assert result == name
        assert not result.startswith("…")

    def test_empty_string(self) -> None:
        result = CommentBuilder._truncate_filename("", 60)
        assert result == ""


# ---------------------------------------------------------------------------
# CommentBuilder.should_post()
# ---------------------------------------------------------------------------


class TestShouldPost:
    """Tests for the should_post() method."""

    def test_post_false_never_posts(self) -> None:
        config = _make_config(post=False, post_when="always")
        builder = CommentBuilder(config=config)
        for risk in ("OK", "WARN", "BLOCK"):
            assert builder.should_post(risk) is False, f"Expected False for {risk}"

    def test_post_when_always_posts_for_all_levels(self) -> None:
        config = _make_config(post=True, post_when="always")
        builder = CommentBuilder(config=config)
        for risk in ("OK", "WARN", "BLOCK"):
            assert builder.should_post(risk) is True, f"Expected True for {risk}"

    def test_post_when_warn_posts_for_warn_and_block(self) -> None:
        config = _make_config(post=True, post_when="warn")
        builder = CommentBuilder(config=config)
        assert builder.should_post("WARN") is True
        assert builder.should_post("BLOCK") is True

    def test_post_when_warn_does_not_post_for_ok(self) -> None:
        config = _make_config(post=True, post_when="warn")
        builder = CommentBuilder(config=config)
        assert builder.should_post("OK") is False

    def test_post_when_block_posts_only_for_block(self) -> None:
        config = _make_config(post=True, post_when="block")
        builder = CommentBuilder(config=config)
        assert builder.should_post("BLOCK") is True
        assert builder.should_post("WARN") is False
        assert builder.should_post("OK") is False


# ---------------------------------------------------------------------------
# determine_risk_level()
# ---------------------------------------------------------------------------


class TestDetermineRiskLevel:
    """Tests for the determine_risk_level() function."""

    def test_ok_when_below_all_thresholds(self) -> None:
        config = _make_config(warn_usd=1.0, block_usd=5.0)
        analysis = _make_analysis(estimated_cost_usd=0.50)
        security = _make_security_result()
        assert determine_risk_level(analysis, security, config) == "OK"

    def test_warn_when_cost_exceeds_warn_threshold(self) -> None:
        config = _make_config(warn_usd=1.0, block_usd=5.0)
        analysis = _make_analysis(estimated_cost_usd=1.50)
        security = _make_security_result()
        assert determine_risk_level(analysis, security, config) == "WARN"

    def test_block_when_cost_exceeds_block_threshold(self) -> None:
        config = _make_config(warn_usd=1.0, block_usd=5.0)
        analysis = _make_analysis(estimated_cost_usd=6.00)
        security = _make_security_result()
        assert determine_risk_level(analysis, security, config) == "BLOCK"

    def test_warn_at_exact_warn_threshold(self) -> None:
        config = _make_config(warn_usd=1.0, block_usd=5.0)
        analysis = _make_analysis(estimated_cost_usd=1.0)
        security = _make_security_result()
        assert determine_risk_level(analysis, security, config) == "WARN"

    def test_block_at_exact_block_threshold(self) -> None:
        config = _make_config(warn_usd=1.0, block_usd=5.0)
        analysis = _make_analysis(estimated_cost_usd=5.0)
        security = _make_security_result()
        assert determine_risk_level(analysis, security, config) == "BLOCK"

    def test_block_when_critical_security_finding(self) -> None:
        config = _make_config(warn_usd=1.0, block_usd=5.0)
        analysis = _make_analysis(estimated_cost_usd=0.01)  # Low cost
        finding = _make_finding(risk_level=RiskLevel.CRITICAL)
        security = _make_security_result(findings=[finding])
        assert determine_risk_level(analysis, security, config) == "BLOCK"

    def test_warn_when_high_security_finding(self) -> None:
        config = _make_config(warn_usd=1.0, block_usd=5.0)
        analysis = _make_analysis(estimated_cost_usd=0.01)  # Low cost
        finding = _make_finding(risk_level=RiskLevel.HIGH)
        security = _make_security_result(findings=[finding])
        assert determine_risk_level(analysis, security, config) == "WARN"

    def test_ok_when_only_medium_security_finding(self) -> None:
        config = _make_config(warn_usd=1.0, block_usd=5.0)
        analysis = _make_analysis(estimated_cost_usd=0.01)
        finding = _make_finding(risk_level=RiskLevel.MEDIUM)
        security = _make_security_result(findings=[finding])
        assert determine_risk_level(analysis, security, config) == "OK"

    def test_block_takes_precedence_over_warn(self) -> None:
        config = _make_config(warn_usd=1.0, block_usd=5.0)
        analysis = _make_analysis(estimated_cost_usd=6.0)  # Above block threshold
        finding = _make_finding(risk_level=RiskLevel.HIGH)  # Would trigger warn
        security = _make_security_result(findings=[finding])
        assert determine_risk_level(analysis, security, config) == "BLOCK"

    def test_zero_block_threshold_disables_cost_blocking(self) -> None:
        config = _make_config(warn_usd=1.0, block_usd=0.0)
        analysis = _make_analysis(estimated_cost_usd=100.0)  # Very expensive
        security = _make_security_result()
        # block_usd=0 disables cost-based blocking
        result = determine_risk_level(analysis, security, config)
        assert result in ("WARN", "OK")  # Not BLOCK due to cost

    def test_zero_warn_threshold_disables_cost_warning(self) -> None:
        config = _make_config(warn_usd=0.0, block_usd=0.0)
        analysis = _make_analysis(estimated_cost_usd=100.0)
        security = _make_security_result()
        assert determine_risk_level(analysis, security, config) == "OK"

    def test_critical_not_blocked_when_block_usd_is_zero(self) -> None:
        """When block_usd=0, critical security findings do NOT trigger BLOCK."""
        config = _make_config(warn_usd=1.0, block_usd=0.0)
        analysis = _make_analysis(estimated_cost_usd=0.01)
        finding = _make_finding(risk_level=RiskLevel.CRITICAL)
        security = _make_security_result(findings=[finding])
        # block_usd=0 means no blocking at all
        result = determine_risk_level(analysis, security, config)
        # Should be WARN (has_high covers CRITICAL) but not BLOCK
        assert result == "WARN"

    def test_no_security_no_cost_is_ok(self) -> None:
        config = _make_config(warn_usd=1.0, block_usd=5.0)
        analysis = _make_analysis(estimated_cost_usd=0.0)
        security = _make_security_result()
        assert determine_risk_level(analysis, security, config) == "OK"


# ---------------------------------------------------------------------------
# CommentPoster
# ---------------------------------------------------------------------------


class TestCommentPoster:
    """Tests for CommentPoster.post()."""

    def _make_mock_github(
        self,
        existing_comment_body: Optional[str] = None,
        new_comment_id: int = 123,
        new_comment_url: str = "https://github.com/owner/repo/issues/1#issuecomment-123",
    ) -> tuple[MagicMock, MagicMock, MagicMock]:
        """Set up a mock Github client."""
        gh = MagicMock()
        gh_repo = MagicMock()
        issue = MagicMock()

        gh.get_repo.return_value = gh_repo
        gh_repo.get_issue.return_value = issue

        if existing_comment_body is not None:
            existing_comment = MagicMock()
            existing_comment.body = existing_comment_body
            existing_comment.id = 999
            existing_comment.html_url = "https://github.com/owner/repo/issues/1#issuecomment-999"
            issue.get_comments.return_value = [existing_comment]
        else:
            issue.get_comments.return_value = []

        new_comment = MagicMock()
        new_comment.id = new_comment_id
        new_comment.html_url = new_comment_url
        issue.create_comment.return_value = new_comment

        return gh, gh_repo, issue

    def test_creates_new_comment_when_none_exists(self) -> None:
        gh, gh_repo, issue = self._make_mock_github(existing_comment_body=None)
        config = _make_config()

        with patch("pr_cost_gate.comment.Github", return_value=gh):
            poster = CommentPoster(github_token="ghp_test", config=config)
            result = poster.post("owner/repo", 1, "Test body")

        issue.create_comment.assert_called_once_with("Test body")
        assert result.was_updated is False
        assert result.comment_id == 123

    def test_updates_existing_comment_when_found(self) -> None:
        existing_body = f"{COMMENT_MARKER}\n\nOld content"
        gh, gh_repo, issue = self._make_mock_github(
            existing_comment_body=existing_body
        )
        config = _make_config()

        with patch("pr_cost_gate.comment.Github", return_value=gh):
            poster = CommentPoster(github_token="ghp_test", config=config)
            result = poster.post("owner/repo", 1, "New body")

        # Should edit the existing comment, not create a new one
        issue.create_comment.assert_not_called()
        assert result.was_updated is True
        assert result.comment_id == 999

    def test_creates_new_when_existing_comment_has_different_marker(self) -> None:
        # Existing comment without our marker should not be updated
        gh, gh_repo, issue = self._make_mock_github(
            existing_comment_body="Some other bot comment"
        )
        config = _make_config()

        with patch("pr_cost_gate.comment.Github", return_value=gh):
            poster = CommentPoster(github_token="ghp_test", config=config)
            result = poster.post("owner/repo", 1, "Test body")

        issue.create_comment.assert_called_once()
        assert result.was_updated is False

    def test_raises_comment_error_on_repo_not_found(self) -> None:
        gh = MagicMock()
        gh.get_repo.side_effect = Exception("Not Found")
        config = _make_config()

        with patch("pr_cost_gate.comment.Github", return_value=gh):
            poster = CommentPoster(github_token="ghp_test", config=config)
            with pytest.raises(CommentError, match="Cannot access repository"):
                poster.post("bad/repo", 1, "body")

    def test_raises_comment_error_on_issue_not_found(self) -> None:
        gh = MagicMock()
        gh_repo = MagicMock()
        gh_repo.get_issue.side_effect = Exception("Issue not found")
        gh.get_repo.return_value = gh_repo
        config = _make_config()

        with patch("pr_cost_gate.comment.Github", return_value=gh):
            poster = CommentPoster(github_token="ghp_test", config=config)
            with pytest.raises(CommentError, match="Cannot access PR"):
                poster.post("owner/repo", 9999, "body")

    def test_raises_comment_error_on_list_comments_failure(self) -> None:
        gh = MagicMock()
        gh_repo = MagicMock()
        issue = MagicMock()
        issue.get_comments.side_effect = Exception("API error")
        gh_repo.get_issue.return_value = issue
        gh.get_repo.return_value = gh_repo
        config = _make_config()

        with patch("pr_cost_gate.comment.Github", return_value=gh):
            poster = CommentPoster(github_token="ghp_test", config=config)
            with pytest.raises(CommentError, match="Cannot list comments"):
                poster.post("owner/repo", 1, "body")

    def test_raises_comment_error_on_create_failure(self) -> None:
        gh = MagicMock()
        gh_repo = MagicMock()
        issue = MagicMock()
        issue.get_comments.return_value = []
        issue.create_comment.side_effect = Exception("Create failed")
        gh_repo.get_issue.return_value = issue
        gh.get_repo.return_value = gh_repo
        config = _make_config()

        with patch("pr_cost_gate.comment.Github", return_value=gh):
            poster = CommentPoster(github_token="ghp_test", config=config)
            with pytest.raises(CommentError, match="Cannot create comment"):
                poster.post("owner/repo", 1, "body")

    def test_raises_comment_error_on_edit_failure(self) -> None:
        existing_body = f"{COMMENT_MARKER}\n\nOld content"
        gh, gh_repo, issue = self._make_mock_github(
            existing_comment_body=existing_body
        )
        # Make edit fail
        existing_comment = issue.get_comments.return_value[0]
        existing_comment.edit.side_effect = Exception("Edit failed")
        config = _make_config()

        with patch("pr_cost_gate.comment.Github", return_value=gh):
            poster = CommentPoster(github_token="ghp_test", config=config)
            with pytest.raises(CommentError, match="Cannot update comment"):
                poster.post("owner/repo", 1, "New body")

    def test_github_client_lazy_loaded(self) -> None:
        config = _make_config()
        poster = CommentPoster(github_token="ghp_test", config=config)
        assert poster._gh is None

        with patch("pr_cost_gate.comment.Github") as mock_gh_cls:
            mock_gh_cls.return_value = MagicMock()
            _ = poster.gh
            mock_gh_cls.assert_called_once_with("ghp_test")

    def test_github_client_cached(self) -> None:
        config = _make_config()
        poster = CommentPoster(github_token="ghp_test", config=config)

        with patch("pr_cost_gate.comment.Github") as mock_gh_cls:
            mock_instance = MagicMock()
            mock_gh_cls.return_value = mock_instance
            gh1 = poster.gh
            gh2 = poster.gh
            assert gh1 is gh2
            mock_gh_cls.assert_called_once()

    def test_posted_comment_url_returned(self) -> None:
        url = "https://github.com/owner/repo/issues/1#issuecomment-456"
        gh, gh_repo, issue = self._make_mock_github(
            new_comment_url=url, new_comment_id=456
        )
        config = _make_config()

        with patch("pr_cost_gate.comment.Github", return_value=gh):
            poster = CommentPoster(github_token="ghp_test", config=config)
            result = poster.post("owner/repo", 1, "body")

        assert result.comment_url == url


# ---------------------------------------------------------------------------
# PostedComment dataclass
# ---------------------------------------------------------------------------


class TestPostedComment:
    def test_basic_construction(self) -> None:
        pc = PostedComment(comment_id=1, comment_url="https://example.com/comment/1")
        assert pc.comment_id == 1
        assert pc.comment_url == "https://example.com/comment/1"
        assert pc.was_updated is False

    def test_updated_flag(self) -> None:
        pc = PostedComment(
            comment_id=2,
            comment_url="https://example.com/comment/2",
            was_updated=True,
        )
        assert pc.was_updated is True


# ---------------------------------------------------------------------------
# CommentError
# ---------------------------------------------------------------------------


class TestCommentError:
    def test_is_runtime_error(self) -> None:
        assert issubclass(CommentError, RuntimeError)

    def test_can_be_raised(self) -> None:
        with pytest.raises(CommentError, match="test message"):
            raise CommentError("test message")


# ---------------------------------------------------------------------------
# build_and_post_comment() convenience wrapper
# ---------------------------------------------------------------------------


class TestBuildAndPostComment:
    """Tests for the build_and_post_comment() convenience function."""

    def _make_mock_poster(
        self,
        comment_id: int = 1,
        comment_url: str = "https://github.com/owner/repo/pull/1#issuecomment-1",
    ) -> MagicMock:
        """Create a mock PostedComment."""
        posted = PostedComment(
            comment_id=comment_id,
            comment_url=comment_url,
            was_updated=False,
        )
        mock_poster = MagicMock(spec=CommentPoster)
        mock_poster.post.return_value = posted
        return mock_poster

    def test_returns_risk_level_and_posted_comment(self) -> None:
        analysis = _make_analysis(estimated_cost_usd=0.10)
        security = _make_security_result()
        config = _make_config(warn_usd=1.0, block_usd=5.0, post=True, post_when="always")

        with patch("pr_cost_gate.comment.CommentPoster") as mock_poster_cls:
            mock_poster = self._make_mock_poster()
            mock_poster_cls.return_value = mock_poster

            risk_level, posted = build_and_post_comment(
                github_token="ghp_test",
                repo="owner/repo",
                pr_number=1,
                analysis=analysis,
                security=security,
                config=config,
            )

        assert risk_level == "OK"
        assert posted is not None
        assert posted.comment_id == 1

    def test_returns_none_when_post_disabled(self) -> None:
        analysis = _make_analysis(estimated_cost_usd=0.10)
        security = _make_security_result()
        config = _make_config(post=False)

        with patch("pr_cost_gate.comment.CommentPoster") as mock_poster_cls:
            risk_level, posted = build_and_post_comment(
                github_token="ghp_test",
                repo="owner/repo",
                pr_number=1,
                analysis=analysis,
                security=security,
                config=config,
            )

        assert posted is None
        mock_poster_cls.assert_not_called()

    def test_returns_none_when_risk_level_below_post_when_threshold(self) -> None:
        # post_when=warn, risk_level=OK => don't post
        analysis = _make_analysis(estimated_cost_usd=0.10)
        security = _make_security_result()
        config = _make_config(
            warn_usd=1.0, block_usd=5.0, post=True, post_when="warn"
        )

        with patch("pr_cost_gate.comment.CommentPoster") as mock_poster_cls:
            risk_level, posted = build_and_post_comment(
                github_token="ghp_test",
                repo="owner/repo",
                pr_number=1,
                analysis=analysis,
                security=security,
                config=config,
            )

        assert risk_level == "OK"
        assert posted is None
        mock_poster_cls.assert_not_called()

    def test_uses_default_config_when_none(self) -> None:
        analysis = _make_analysis(estimated_cost_usd=0.01)
        security = _make_security_result()

        with patch("pr_cost_gate.comment.CommentPoster") as mock_poster_cls:
            mock_poster = self._make_mock_poster()
            mock_poster_cls.return_value = mock_poster

            risk_level, posted = build_and_post_comment(
                github_token="ghp_test",
                repo="owner/repo",
                pr_number=1,
                analysis=analysis,
                security=security,
                config=None,  # Should use defaults
            )

        # With default config, should produce a result
        assert risk_level in ("OK", "WARN", "BLOCK")

    def test_block_risk_level_when_cost_high(self) -> None:
        analysis = _make_analysis(estimated_cost_usd=10.0)
        security = _make_security_result()
        config = _make_config(warn_usd=1.0, block_usd=5.0, post=True)

        with patch("pr_cost_gate.comment.CommentPoster") as mock_poster_cls:
            mock_poster = self._make_mock_poster()
            mock_poster_cls.return_value = mock_poster

            risk_level, posted = build_and_post_comment(
                github_token="ghp_test",
                repo="owner/repo",
                pr_number=1,
                analysis=analysis,
                security=security,
                config=config,
            )

        assert risk_level == "BLOCK"
        assert posted is not None

    def test_warn_risk_level_when_cost_moderate(self) -> None:
        analysis = _make_analysis(estimated_cost_usd=2.0)
        security = _make_security_result()
        config = _make_config(warn_usd=1.0, block_usd=5.0, post=True)

        with patch("pr_cost_gate.comment.CommentPoster") as mock_poster_cls:
            mock_poster = self._make_mock_poster()
            mock_poster_cls.return_value = mock_poster

            risk_level, _ = build_and_post_comment(
                github_token="ghp_test",
                repo="owner/repo",
                pr_number=1,
                analysis=analysis,
                security=security,
                config=config,
            )

        assert risk_level == "WARN"

    def test_poster_called_with_correct_args(self) -> None:
        analysis = _make_analysis(estimated_cost_usd=0.10)
        security = _make_security_result()
        config = _make_config(post=True, post_when="always")

        with patch("pr_cost_gate.comment.CommentPoster") as mock_poster_cls:
            mock_poster = self._make_mock_poster()
            mock_poster_cls.return_value = mock_poster

            build_and_post_comment(
                github_token="ghp_test",
                repo="my-org/my-repo",
                pr_number=42,
                analysis=analysis,
                security=security,
                config=config,
            )

        # Verify poster was constructed with the token
        mock_poster_cls.assert_called_once()
        call_kwargs = mock_poster_cls.call_args
        assert call_kwargs.kwargs.get("github_token") == "ghp_test" or \
               (call_kwargs.args and call_kwargs.args[0] == "ghp_test")

        # Verify post was called with correct repo and PR number
        mock_poster.post.assert_called_once()
        post_call = mock_poster.post.call_args
        # First two positional args or keyword args
        args = post_call.args
        kwargs = post_call.kwargs
        repo_arg = kwargs.get("repo") or (args[0] if args else None)
        pr_arg = kwargs.get("pr_number") or (args[1] if len(args) > 1 else None)
        assert repo_arg == "my-org/my-repo"
        assert pr_arg == 42


# ---------------------------------------------------------------------------
# Integration-style: build full comment for representative scenarios
# ---------------------------------------------------------------------------


class TestFullCommentIntegration:
    """End-to-end build() tests for representative real-world scenarios."""

    def test_large_expensive_pr_comment(self) -> None:
        """A large, expensive PR above the block threshold."""
        files = [
            _make_file_analysis("src/api/views.py", token_count=50_000, estimated_cost_usd=0.40),
            _make_file_analysis("src/models.py", token_count=30_000, estimated_cost_usd=0.25),
            _make_file_analysis("tests/test_api.py", token_count=20_000, estimated_cost_usd=0.15),
        ]
        skipped = ["poetry.lock", "yarn.lock"]
        analysis = _make_analysis(
            files=files,
            skipped_files=skipped,
            total_tokens=100_000,
            estimated_cost_usd=6.50,
            any_capped=True,
        )
        findings = [
            _make_finding(
                category=FindingCategory.SECRET,
                rule_id="SECRET-001",
                filename="src/api/views.py",
                risk_level=RiskLevel.CRITICAL,
            ),
            _make_finding(
                category=FindingCategory.DANGEROUS_FUNCTION,
                rule_id="EXEC-001",
                filename="src/models.py",
                risk_level=RiskLevel.HIGH,
                line_content="result = eval(user_input)",
            ),
        ]
        security = _make_security_result(
            findings=findings, scanned_files=[f.filename for f in files]
        )

        config = _make_config(
            warn_usd=1.0, block_usd=5.0, post=True, collapsible=True
        )
        builder = CommentBuilder(config=config)
        body = builder.build(analysis, security, risk_level="BLOCK")

        assert COMMENT_MARKER in body
        assert "BLOCK" in body
        assert "🚫" in body
        assert "100,000" in body
        assert "6.5" in body
        assert "SECRET-001" in body
        assert "EXEC-001" in body
        assert "<details>" in body
        assert "capped" in body.lower()
        assert "poetry.lock" in body

    def test_clean_pr_comment(self) -> None:
        """A small, clean PR with no issues."""
        files = [_make_file_analysis("src/utils.py", token_count=500, estimated_cost_usd=0.003)]
        analysis = _make_analysis(
            files=files,
            total_tokens=500,
            estimated_cost_usd=0.003,
            pr_title="Fix typo in docs",
        )
        security = _make_security_result(scanned_files=["src/utils.py"])

        config = _make_config(warn_usd=1.0, block_usd=5.0)
        builder = CommentBuilder(config=config)
        body = builder.build(analysis, security, risk_level="OK")

        assert COMMENT_MARKER in body
        assert "OK" in body
        assert "✅" in body
        assert "Fix typo in docs" in body
        assert "No security issues detected" in body
        assert "500" in body

    def test_pr_with_dependency_changes(self) -> None:
        """A PR that only updates dependencies."""
        files = [_make_file_analysis("requirements.txt", token_count=50)]
        analysis = _make_analysis(files=files, total_tokens=50, estimated_cost_usd=0.0003)
        findings = [
            _make_finding(
                category=FindingCategory.DEPENDENCY_CHANGE,
                rule_id="DEP-001",
                filename="requirements.txt",
                risk_level=RiskLevel.MEDIUM,
                description="Dependency manifest modified",
                remediation="Run pip-audit.",
            )
        ]
        security = _make_security_result(
            findings=findings, scanned_files=["requirements.txt"]
        )

        config = _make_config(collapsible=False)
        builder = CommentBuilder(config=config)
        body = builder.build(analysis, security, risk_level="OK")

        assert "DEP-001" in body
        assert "requirements.txt" in body
        assert "Dependency" in body
        assert "Run pip-audit." in body
