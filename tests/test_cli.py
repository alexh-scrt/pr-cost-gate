"""Unit tests for pr_cost_gate.cli.

Covers:
- _resolve_token() from args and environment variables
- _resolve_repo() from args and environment variables
- _resolve_pr_number() from args and environment variables
- _resolve_config_path() from args and environment variables
- _load_and_merge_config() with various overrides
- _print_analysis_summary() output
- _set_github_output() with/without GITHUB_OUTPUT
- _set_github_action_outputs() field writing
- main() exit codes: OK, BLOCK, CONFIG_ERROR
- main() missing required arguments
- main() with mocked run()
- run() orchestration with mocked dependencies
"""

from __future__ import annotations

import os
from io import StringIO
from pathlib import Path
from typing import Optional
from unittest.mock import MagicMock, call, patch

import pytest

from pr_cost_gate.analyzer import AnalyzerError, PRAnalysisResult, PRNotFoundError
from pr_cost_gate.cli import (
    EXIT_BLOCK,
    EXIT_CONFIG_ERROR,
    EXIT_OK,
    _build_parser,
    _load_and_merge_config,
    _resolve_config_path,
    _resolve_pr_number,
    _resolve_repo,
    _resolve_token,
    _set_github_action_outputs,
    _set_github_output,
    main,
    run,
)
from pr_cost_gate.comment import CommentError, PostedComment
from pr_cost_gate.config import (
    CommentConfig,
    GateConfig,
    SecurityConfig,
    ThresholdConfig,
)
from pr_cost_gate.security import (
    FindingCategory,
    RiskLevel,
    SecurityFinding,
    SecurityScanResult,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_analysis(
    total_tokens: int = 1000,
    estimated_cost_usd: float = 0.01,
    pr_number: int = 1,
    repo: str = "owner/repo",
    model: str = "gpt-4o",
    pr_title: str = "Test PR",
    pr_url: str = "https://github.com/owner/repo/pull/1",
    base_branch: str = "main",
    head_branch: str = "feature/test",
    any_capped: bool = False,
) -> PRAnalysisResult:
    from pr_cost_gate.analyzer import FileAnalysis
    return PRAnalysisResult(
        repo=repo,
        pr_number=pr_number,
        model=model,
        files=[],
        skipped_files=[],
        total_tokens=total_tokens,
        estimated_cost_usd=estimated_cost_usd,
        input_tokens=total_tokens,
        output_tokens=int(total_tokens * 0.2),
        any_capped=any_capped,
        pr_title=pr_title,
        pr_url=pr_url,
        base_branch=base_branch,
        head_branch=head_branch,
    )


def _make_security(findings_count: int = 0) -> SecurityScanResult:
    result = SecurityScanResult()
    for i in range(findings_count):
        result.findings.append(
            SecurityFinding(
                category=FindingCategory.SECRET,
                rule_id=f"SECRET-00{i}",
                description="Test",
                filename="app.py",
                line_content="api_key = 'x'",
                line_number=i + 1,
                risk_level=RiskLevel.HIGH,
                remediation="Use env var.",
            )
        )
    result._update_highest_risk()
    return result


def _make_posted_comment(
    comment_id: int = 1,
    comment_url: str = "https://github.com/owner/repo/pull/1#issuecomment-1",
) -> PostedComment:
    return PostedComment(
        comment_id=comment_id,
        comment_url=comment_url,
        was_updated=False,
    )


# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------


class TestExitCodes:
    def test_exit_ok_is_zero(self) -> None:
        assert EXIT_OK == 0

    def test_exit_block_is_one(self) -> None:
        assert EXIT_BLOCK == 1

    def test_exit_config_error_is_two(self) -> None:
        assert EXIT_CONFIG_ERROR == 2


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


class TestBuildParser:
    """Tests for the CLI argument parser."""

    def test_parser_created(self) -> None:
        parser = _build_parser()
        assert parser is not None

    def test_parse_token_arg(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["--token", "ghp_abc", "--repo", "o/r", "--pr", "1"])
        assert args.token == "ghp_abc"

    def test_parse_repo_arg(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["--token", "t", "--repo", "owner/repo", "--pr", "1"])
        assert args.repo == "owner/repo"

    def test_parse_pr_arg(self) -> None:
        parser = _build_parser()
        args = parser.parse_args(["--token", "t", "--repo", "o/r", "--pr", "42"])
        assert args.pr_number == 42

    def test_parse_model_arg(self) -> None:
        parser = _build_parser()
        args = parser.parse_args([
            "--token", "t", "--repo", "o/r", "--pr", "1", "--model", "claude-3-opus"
        ])
        assert args.model == "claude-3-opus"

    def test_parse_warn_threshold(self) -> None:
        parser = _build_parser()
        args = parser.parse_args([
            "--token", "t", "--repo", "o/r", "--pr", "1", "--warn-threshold", "0.5"
        ])
        assert args.warn_threshold_usd == pytest.approx(0.5)

    def test_parse_block_threshold(self) -> None:
        parser = _build_parser()
        args = parser.parse_args([
            "--token", "t", "--repo", "o/r", "--pr", "1", "--block-threshold", "2.0"
        ])
        assert args.block_threshold_usd == pytest.approx(2.0)

    def test_parse_no_comment_flag(self) -> None:
        parser = _build_parser()
        args = parser.parse_args([
            "--token", "t", "--repo", "o/r", "--pr", "1", "--no-comment"
        ])
        assert args.no_comment is True

    def test_parse_no_security_flag(self) -> None:
        parser = _build_parser()
        args = parser.parse_args([
            "--token", "t", "--repo", "o/r", "--pr", "1", "--no-security"
        ])
        assert args.no_security is True

    def test_parse_verbose_flag(self) -> None:
        parser = _build_parser()
        args = parser.parse_args([
            "--token", "t", "--repo", "o/r", "--pr", "1", "--verbose"
        ])
        assert args.verbose is True

    def test_parse_config_path(self) -> None:
        parser = _build_parser()
        args = parser.parse_args([
            "--token", "t", "--repo", "o/r", "--pr", "1",
            "--config", "custom_config.yml",
        ])
        assert args.config_path == "custom_config.yml"

    def test_defaults_are_none(self) -> None:
        parser = _build_parser()
        args = parser.parse_args([])
        assert args.token is None
        assert args.repo is None
        assert args.pr_number is None
        assert args.model is None
        assert args.warn_threshold_usd is None
        assert args.block_threshold_usd is None
        assert args.no_comment is False
        assert args.no_security is False
        assert args.verbose is False

    def test_invalid_model_rejected(self) -> None:
        parser = _build_parser()
        with pytest.raises(SystemExit):
            parser.parse_args(["--token", "t", "--repo", "o/r", "--pr", "1",
                               "--model", "gpt-99-ultra"])


# ---------------------------------------------------------------------------
# Resolution helpers
# ---------------------------------------------------------------------------


class TestResolveToken:
    def test_from_args(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("INPUT_GITHUB_TOKEN", raising=False)
        parser = _build_parser()
        args = parser.parse_args(["--token", "ghp_from_args"])
        assert _resolve_token(args) == "ghp_from_args"

    def test_from_github_token_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_from_env")
        monkeypatch.delenv("INPUT_GITHUB_TOKEN", raising=False)
        parser = _build_parser()
        args = parser.parse_args([])
        assert _resolve_token(args) == "ghp_from_env"

    def test_from_input_github_token_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.setenv("INPUT_GITHUB_TOKEN", "ghp_input_token")
        parser = _build_parser()
        args = parser.parse_args([])
        assert _resolve_token(args) == "ghp_input_token"

    def test_args_takes_precedence_over_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GITHUB_TOKEN", "env_token")
        parser = _build_parser()
        args = parser.parse_args(["--token", "arg_token"])
        assert _resolve_token(args) == "arg_token"

    def test_returns_none_when_not_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GITHUB_TOKEN", raising=False)
        monkeypatch.delenv("INPUT_GITHUB_TOKEN", raising=False)
        parser = _build_parser()
        args = parser.parse_args([])
        assert _resolve_token(args) is None


class TestResolveRepo:
    def test_from_args(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        parser = _build_parser()
        args = parser.parse_args(["--repo", "owner/repo"])
        assert _resolve_repo(args) == "owner/repo"

    def test_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GITHUB_REPOSITORY", "env-owner/env-repo")
        parser = _build_parser()
        args = parser.parse_args([])
        assert _resolve_repo(args) == "env-owner/env-repo"

    def test_args_takes_precedence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("GITHUB_REPOSITORY", "env-owner/env-repo")
        parser = _build_parser()
        args = parser.parse_args(["--repo", "arg-owner/arg-repo"])
        assert _resolve_repo(args) == "arg-owner/arg-repo"

    def test_returns_none_when_not_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GITHUB_REPOSITORY", raising=False)
        parser = _build_parser()
        args = parser.parse_args([])
        assert _resolve_repo(args) is None


class TestResolvePrNumber:
    def test_from_args(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PR_NUMBER", raising=False)
        monkeypatch.delenv("INPUT_PR_NUMBER", raising=False)
        parser = _build_parser()
        args = parser.parse_args(["--pr", "42"])
        assert _resolve_pr_number(args) == 42

    def test_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PR_NUMBER", "99")
        monkeypatch.delenv("INPUT_PR_NUMBER", raising=False)
        parser = _build_parser()
        args = parser.parse_args([])
        assert _resolve_pr_number(args) == 99

    def test_args_takes_precedence(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PR_NUMBER", "99")
        parser = _build_parser()
        args = parser.parse_args(["--pr", "42"])
        assert _resolve_pr_number(args) == 42

    def test_returns_none_when_not_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PR_NUMBER", raising=False)
        monkeypatch.delenv("INPUT_PR_NUMBER", raising=False)
        parser = _build_parser()
        args = parser.parse_args([])
        assert _resolve_pr_number(args) is None

    def test_invalid_env_returns_none(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PR_NUMBER", "not-a-number")
        monkeypatch.delenv("INPUT_PR_NUMBER", raising=False)
        parser = _build_parser()
        args = parser.parse_args([])
        assert _resolve_pr_number(args) is None


class TestResolveConfigPath:
    def test_from_args(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PCG_CONFIG_PATH", raising=False)
        monkeypatch.delenv("INPUT_CONFIG_PATH", raising=False)
        parser = _build_parser()
        args = parser.parse_args(["--config", "my-config.yml"])
        assert _resolve_config_path(args) == "my-config.yml"

    def test_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.setenv("PCG_CONFIG_PATH", "env-config.yml")
        monkeypatch.delenv("INPUT_CONFIG_PATH", raising=False)
        parser = _build_parser()
        args = parser.parse_args([])
        assert _resolve_config_path(args) == "env-config.yml"

    def test_default_when_not_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("PCG_CONFIG_PATH", raising=False)
        monkeypatch.delenv("INPUT_CONFIG_PATH", raising=False)
        parser = _build_parser()
        args = parser.parse_args([])
        assert _resolve_config_path(args) == ".pr_cost_gate.yml"


# ---------------------------------------------------------------------------
# _load_and_merge_config
# ---------------------------------------------------------------------------


class TestLoadAndMergeConfig:
    """Tests for _load_and_merge_config()."""

    def _make_args(self, **kwargs):
        """Create a simple namespace with default values."""
        import argparse
        defaults = {
            "model": None,
            "warn_threshold_usd": None,
            "block_threshold_usd": None,
            "no_comment": False,
            "no_security": False,
        }
        defaults.update(kwargs)
        return argparse.Namespace(**defaults)

    def test_defaults_when_no_overrides(self, tmp_path: Path,
                                        monkeypatch: pytest.MonkeyPatch) -> None:
        for key in ["PCG_MODEL", "PCG_WARN_THRESHOLD_USD",
                    "PCG_BLOCK_THRESHOLD_USD", "PCG_POST_COMMENT",
                    "PCG_SECURITY_SCAN"]:
            monkeypatch.delenv(key, raising=False)
        config_path = str(tmp_path / ".pr_cost_gate.yml")  # doesn't exist
        args = self._make_args()
        config = _load_and_merge_config(args, config_path)
        assert config.model == "gpt-4o"  # default

    def test_model_override_from_args(self, tmp_path: Path,
                                      monkeypatch: pytest.MonkeyPatch) -> None:
        for key in ["PCG_MODEL", "PCG_WARN_THRESHOLD_USD",
                    "PCG_BLOCK_THRESHOLD_USD", "PCG_POST_COMMENT",
                    "PCG_SECURITY_SCAN"]:
            monkeypatch.delenv(key, raising=False)
        config_path = str(tmp_path / ".pr_cost_gate.yml")
        args = self._make_args(model="claude-3-haiku")
        config = _load_and_merge_config(args, config_path)
        assert config.model == "claude-3-haiku"

    def test_warn_threshold_override_from_args(self, tmp_path: Path,
                                               monkeypatch: pytest.MonkeyPatch) -> None:
        for key in ["PCG_MODEL", "PCG_WARN_THRESHOLD_USD",
                    "PCG_BLOCK_THRESHOLD_USD", "PCG_POST_COMMENT",
                    "PCG_SECURITY_SCAN"]:
            monkeypatch.delenv(key, raising=False)
        config_path = str(tmp_path / ".pr_cost_gate.yml")
        args = self._make_args(warn_threshold_usd=0.5)
        config = _load_and_merge_config(args, config_path)
        assert config.thresholds.warn_usd == pytest.approx(0.5)

    def test_block_threshold_override_from_args(self, tmp_path: Path,
                                                monkeypatch: pytest.MonkeyPatch) -> None:
        for key in ["PCG_MODEL", "PCG_WARN_THRESHOLD_USD",
                    "PCG_BLOCK_THRESHOLD_USD", "PCG_POST_COMMENT",
                    "PCG_SECURITY_SCAN"]:
            monkeypatch.delenv(key, raising=False)
        config_path = str(tmp_path / ".pr_cost_gate.yml")
        args = self._make_args(block_threshold_usd=10.0)
        config = _load_and_merge_config(args, config_path)
        assert config.thresholds.block_usd == pytest.approx(10.0)

    def test_no_comment_override(self, tmp_path: Path,
                                 monkeypatch: pytest.MonkeyPatch) -> None:
        for key in ["PCG_MODEL", "PCG_WARN_THRESHOLD_USD",
                    "PCG_BLOCK_THRESHOLD_USD", "PCG_POST_COMMENT",
                    "PCG_SECURITY_SCAN"]:
            monkeypatch.delenv(key, raising=False)
        config_path = str(tmp_path / ".pr_cost_gate.yml")
        args = self._make_args(no_comment=True)
        config = _load_and_merge_config(args, config_path)
        assert config.comment.post is False

    def test_no_security_override(self, tmp_path: Path,
                                  monkeypatch: pytest.MonkeyPatch) -> None:
        for key in ["PCG_MODEL", "PCG_WARN_THRESHOLD_USD",
                    "PCG_BLOCK_THRESHOLD_USD", "PCG_POST_COMMENT",
                    "PCG_SECURITY_SCAN"]:
            monkeypatch.delenv(key, raising=False)
        config_path = str(tmp_path / ".pr_cost_gate.yml")
        args = self._make_args(no_security=True)
        config = _load_and_merge_config(args, config_path)
        assert config.security.enabled is False

    def test_config_file_loaded(self, tmp_path: Path,
                                monkeypatch: pytest.MonkeyPatch) -> None:
        for key in ["PCG_MODEL", "PCG_WARN_THRESHOLD_USD",
                    "PCG_BLOCK_THRESHOLD_USD", "PCG_POST_COMMENT",
                    "PCG_SECURITY_SCAN"]:
            monkeypatch.delenv(key, raising=False)
        config_file = tmp_path / "config.yml"
        config_file.write_text("model: claude-3-5-sonnet\n", encoding="utf-8")
        args = self._make_args()
        config = _load_and_merge_config(args, str(config_file))
        assert config.model == "claude-3-5-sonnet"

    def test_cli_args_override_file(self, tmp_path: Path,
                                   monkeypatch: pytest.MonkeyPatch) -> None:
        for key in ["PCG_MODEL", "PCG_WARN_THRESHOLD_USD",
                    "PCG_BLOCK_THRESHOLD_USD", "PCG_POST_COMMENT",
                    "PCG_SECURITY_SCAN"]:
            monkeypatch.delenv(key, raising=False)
        config_file = tmp_path / "config.yml"
        config_file.write_text("model: claude-3-opus\n", encoding="utf-8")
        args = self._make_args(model="gpt-4-turbo")
        config = _load_and_merge_config(args, str(config_file))
        # CLI arg should win over file
        assert config.model == "gpt-4-turbo"


# ---------------------------------------------------------------------------
# _set_github_output
# ---------------------------------------------------------------------------


class TestSetGithubOutput:
    def test_writes_to_file_when_env_set(self, tmp_path: Path,
                                         monkeypatch: pytest.MonkeyPatch) -> None:
        output_file = tmp_path / "github_output"
        output_file.write_text("", encoding="utf-8")
        monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))
        _set_github_output("risk_level", "WARN")
        content = output_file.read_text(encoding="utf-8")
        assert "risk_level=WARN" in content

    def test_no_op_when_env_not_set(self, monkeypatch: pytest.MonkeyPatch) -> None:
        monkeypatch.delenv("GITHUB_OUTPUT", raising=False)
        # Should not raise
        _set_github_output("key", "value")

    def test_appends_to_existing_file(self, tmp_path: Path,
                                      monkeypatch: pytest.MonkeyPatch) -> None:
        output_file = tmp_path / "github_output"
        output_file.write_text("existing=value\n", encoding="utf-8")
        monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))
        _set_github_output("new_key", "new_value")
        content = output_file.read_text(encoding="utf-8")
        assert "existing=value" in content
        assert "new_key=new_value" in content


class TestSetGithubActionOutputs:
    def test_all_outputs_written(self, tmp_path: Path,
                                  monkeypatch: pytest.MonkeyPatch) -> None:
        output_file = tmp_path / "github_output"
        output_file.write_text("", encoding="utf-8")
        monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

        analysis = _make_analysis(total_tokens=5000, estimated_cost_usd=0.05)
        security = _make_security(findings_count=2)
        posted = _make_posted_comment(
            comment_url="https://github.com/owner/repo/pull/1#issuecomment-1"
        )

        _set_github_action_outputs(analysis, security, "WARN", posted)
        content = output_file.read_text(encoding="utf-8")

        assert "total_tokens=5000" in content
        assert "risk_level=WARN" in content
        assert "security_findings=2" in content
        assert "comment_url=https://github.com/owner/repo/pull/1#issuecomment-1" in content

    def test_empty_comment_url_when_no_comment(self, tmp_path: Path,
                                               monkeypatch: pytest.MonkeyPatch) -> None:
        output_file = tmp_path / "github_output"
        output_file.write_text("", encoding="utf-8")
        monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

        analysis = _make_analysis()
        security = _make_security()
        _set_github_action_outputs(analysis, security, "OK", None)
        content = output_file.read_text(encoding="utf-8")
        assert "comment_url=\n" in content or "comment_url=" in content


# ---------------------------------------------------------------------------
# main() — missing required inputs
# ---------------------------------------------------------------------------


class TestMainMissingInputs:
    """Test that main() returns EXIT_CONFIG_ERROR when required inputs are missing."""

    def _clean_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for key in ["GITHUB_TOKEN", "INPUT_GITHUB_TOKEN", "GITHUB_REPOSITORY",
                    "PR_NUMBER", "INPUT_PR_NUMBER", "PCG_MODEL",
                    "PCG_WARN_THRESHOLD_USD", "PCG_BLOCK_THRESHOLD_USD",
                    "PCG_POST_COMMENT", "PCG_SECURITY_SCAN", "PCG_CONFIG_PATH",
                    "INPUT_CONFIG_PATH"]:
            monkeypatch.delenv(key, raising=False)

    def test_missing_token_returns_config_error(self,
                                                monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        exit_code = main(["--repo", "owner/repo", "--pr", "1"])
        assert exit_code == EXIT_CONFIG_ERROR

    def test_missing_repo_returns_config_error(self,
                                               monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        exit_code = main(["--token", "ghp_test", "--pr", "1"])
        assert exit_code == EXIT_CONFIG_ERROR

    def test_missing_pr_number_returns_config_error(self,
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        exit_code = main(["--token", "ghp_test", "--repo", "owner/repo"])
        assert exit_code == EXIT_CONFIG_ERROR

    def test_invalid_pr_number_returns_config_error(self,
                                                    monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        # Negative PR number
        exit_code = main(["--token", "ghp_test", "--repo", "owner/repo", "--pr", "-1"])
        assert exit_code == EXIT_CONFIG_ERROR

    def test_invalid_repo_format_returns_config_error(self,
                                                      monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        exit_code = main(["--token", "ghp_test", "--repo", "invalid-repo", "--pr", "1"])
        assert exit_code == EXIT_CONFIG_ERROR

    def test_token_from_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """When token is provided via env var, should not fail on token check."""
        self._clean_env(monkeypatch)
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_from_env")
        # Should proceed past token check (will fail on other things)
        # Just verify it doesn't return EXIT_CONFIG_ERROR=2 for missing token
        # It will fail later with EXIT_BLOCK=1 because of missing repo
        exit_code = main(["--pr", "1"])  # no --repo
        assert exit_code == EXIT_CONFIG_ERROR  # still fails for missing repo


# ---------------------------------------------------------------------------
# main() — success and block scenarios
# ---------------------------------------------------------------------------


class TestMainWithMockedRun:
    """Test main() with a mocked run() function."""

    def _base_args(self) -> list[str]:
        return ["--token", "ghp_test", "--repo", "owner/repo", "--pr", "1"]

    def _clean_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for key in ["GITHUB_TOKEN", "INPUT_GITHUB_TOKEN", "GITHUB_REPOSITORY",
                    "PR_NUMBER", "INPUT_PR_NUMBER", "PCG_MODEL",
                    "PCG_WARN_THRESHOLD_USD", "PCG_BLOCK_THRESHOLD_USD",
                    "PCG_POST_COMMENT", "PCG_SECURITY_SCAN", "PCG_CONFIG_PATH",
                    "INPUT_CONFIG_PATH", "GITHUB_OUTPUT"]:
            monkeypatch.delenv(key, raising=False)

    def test_ok_risk_level_returns_exit_ok(self,
                                           monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        analysis = _make_analysis(estimated_cost_usd=0.01)
        security = _make_security()
        posted = _make_posted_comment()

        with patch("pr_cost_gate.cli.run", return_value=("OK", analysis, security, posted)):
            exit_code = main(self._base_args())

        assert exit_code == EXIT_OK

    def test_warn_risk_level_returns_exit_ok(self,
                                             monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        analysis = _make_analysis(estimated_cost_usd=2.0)
        security = _make_security()
        posted = _make_posted_comment()

        with patch("pr_cost_gate.cli.run", return_value=("WARN", analysis, security, posted)):
            exit_code = main(self._base_args())

        assert exit_code == EXIT_OK  # WARN still exits 0

    def test_block_risk_level_returns_exit_block(self,
                                                 monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        analysis = _make_analysis(estimated_cost_usd=10.0)
        security = _make_security()
        posted = _make_posted_comment()

        with patch("pr_cost_gate.cli.run", return_value=("BLOCK", analysis, security, posted)):
            exit_code = main(self._base_args())

        assert exit_code == EXIT_BLOCK

    def test_pr_not_found_returns_exit_block(self,
                                             monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)

        with patch("pr_cost_gate.cli.run", side_effect=PRNotFoundError("PR not found")):
            exit_code = main(self._base_args())

        assert exit_code == EXIT_BLOCK

    def test_analyzer_error_returns_exit_block(self,
                                               monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)

        with patch("pr_cost_gate.cli.run", side_effect=AnalyzerError("API error")):
            exit_code = main(self._base_args())

        assert exit_code == EXIT_BLOCK

    def test_unexpected_error_returns_exit_block(self,
                                                 monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)

        with patch("pr_cost_gate.cli.run", side_effect=RuntimeError("Unexpected")):
            exit_code = main(self._base_args())

        assert exit_code == EXIT_BLOCK

    def test_config_error_returns_exit_config_error(self,
                                                    monkeypatch: pytest.MonkeyPatch,
                                                    tmp_path: Path) -> None:
        self._clean_env(monkeypatch)
        bad_config = tmp_path / "bad.yml"
        bad_config.write_text("model: gpt-99\n", encoding="utf-8")

        exit_code = main(self._base_args() + ["--config", str(bad_config)])
        assert exit_code == EXIT_CONFIG_ERROR

    def test_github_action_outputs_written_on_success(self,
                                                      monkeypatch: pytest.MonkeyPatch,
                                                      tmp_path: Path) -> None:
        self._clean_env(monkeypatch)
        output_file = tmp_path / "github_output"
        output_file.write_text("", encoding="utf-8")
        monkeypatch.setenv("GITHUB_OUTPUT", str(output_file))

        analysis = _make_analysis(total_tokens=3000, estimated_cost_usd=0.03)
        security = _make_security()
        posted = _make_posted_comment()

        with patch("pr_cost_gate.cli.run", return_value=("OK", analysis, security, posted)):
            main(self._base_args())

        content = output_file.read_text(encoding="utf-8")
        assert "total_tokens=3000" in content
        assert "risk_level=OK" in content


# ---------------------------------------------------------------------------
# run() orchestration
# ---------------------------------------------------------------------------


class TestRun:
    """Tests for the run() orchestration function."""

    def _mock_dependencies(
        self,
        analysis: Optional[PRAnalysisResult] = None,
        security: Optional[SecurityScanResult] = None,
        risk_level: str = "OK",
        posted: Optional[PostedComment] = None,
    ):
        """Return a context manager that patches analyze_pr, scan_files, and build_and_post_comment."""
        if analysis is None:
            analysis = _make_analysis()
        if security is None:
            security = _make_security()
        if posted is None:
            posted = _make_posted_comment()

        return (
            patch("pr_cost_gate.cli.analyze_pr", return_value=analysis),
            patch("pr_cost_gate.cli.scan_files", return_value=security),
            patch(
                "pr_cost_gate.cli.build_and_post_comment",
                return_value=(risk_level, posted),
            ),
        )

    def test_run_returns_correct_risk_level(self) -> None:
        analysis = _make_analysis(estimated_cost_usd=0.01)
        security = _make_security()
        posted = _make_posted_comment()
        config = GateConfig()

        with patch("pr_cost_gate.cli.analyze_pr", return_value=analysis), \
             patch("pr_cost_gate.cli.scan_files", return_value=security), \
             patch("pr_cost_gate.cli.build_and_post_comment", return_value=("OK", posted)):
            risk_level, result_analysis, result_security, result_posted = run(
                token="ghp_test",
                repo="owner/repo",
                pr_number=1,
                config=config,
            )

        assert risk_level == "OK"
        assert result_analysis is analysis
        assert result_security is security
        assert result_posted is posted

    def test_run_skips_security_scan_when_disabled(self) -> None:
        config = GateConfig(
            security=SecurityConfig(enabled=False)
        )
        analysis = _make_analysis()
        posted = _make_posted_comment()

        with patch("pr_cost_gate.cli.analyze_pr", return_value=analysis), \
             patch("pr_cost_gate.cli.scan_files") as mock_scan, \
             patch("pr_cost_gate.cli.build_and_post_comment", return_value=("OK", posted)):
            run(
                token="ghp_test",
                repo="owner/repo",
                pr_number=1,
                config=config,
            )
            # scan_files should NOT be called when security is disabled
            mock_scan.assert_not_called()

    def test_run_skips_comment_when_disabled(self) -> None:
        config = GateConfig(
            comment=CommentConfig(post=False)
        )
        analysis = _make_analysis()
        security = _make_security()

        with patch("pr_cost_gate.cli.analyze_pr", return_value=analysis), \
             patch("pr_cost_gate.cli.scan_files", return_value=security), \
             patch("pr_cost_gate.cli.build_and_post_comment") as mock_post:
            risk_level, _, _, posted = run(
                token="ghp_test",
                repo="owner/repo",
                pr_number=1,
                config=config,
            )
            # build_and_post_comment should NOT be called when comment.post=False
            mock_post.assert_not_called()
            assert posted is None

    def test_run_comment_error_is_non_fatal(self) -> None:
        """CommentError during posting should log a warning but not raise."""
        config = GateConfig()
        analysis = _make_analysis()
        security = _make_security()

        with patch("pr_cost_gate.cli.analyze_pr", return_value=analysis), \
             patch("pr_cost_gate.cli.scan_files", return_value=security), \
             patch(
                 "pr_cost_gate.cli.build_and_post_comment",
                 side_effect=CommentError("Cannot post comment")
             ):
            # Should not raise, just warn
            risk_level, _, _, posted = run(
                token="ghp_test",
                repo="owner/repo",
                pr_number=1,
                config=config,
            )
            assert posted is None

    def test_run_passes_config_to_analyzer(self) -> None:
        config = GateConfig(model="claude-3-haiku")
        analysis = _make_analysis(model="claude-3-haiku")
        security = _make_security()
        posted = _make_posted_comment()

        with patch("pr_cost_gate.cli.analyze_pr", return_value=analysis) as mock_analyze, \
             patch("pr_cost_gate.cli.scan_files", return_value=security), \
             patch("pr_cost_gate.cli.build_and_post_comment", return_value=("OK", posted)):
            run(
                token="ghp_test",
                repo="owner/repo",
                pr_number=42,
                config=config,
            )
            # Verify config was passed to analyze_pr
            call_kwargs = mock_analyze.call_args
            assert call_kwargs.kwargs.get("config") is config or \
                   config in call_kwargs.args

    def test_run_propagates_pr_not_found_error(self) -> None:
        config = GateConfig()
        with patch(
            "pr_cost_gate.cli.analyze_pr",
            side_effect=PRNotFoundError("PR not found")
        ):
            with pytest.raises(PRNotFoundError):
                run(
                    token="ghp_test",
                    repo="owner/repo",
                    pr_number=9999,
                    config=config,
                )

    def test_run_propagates_analyzer_error(self) -> None:
        config = GateConfig()
        with patch(
            "pr_cost_gate.cli.analyze_pr",
            side_effect=AnalyzerError("API error")
        ):
            with pytest.raises(AnalyzerError):
                run(
                    token="ghp_test",
                    repo="owner/repo",
                    pr_number=1,
                    config=config,
                )


# ---------------------------------------------------------------------------
# Integration-style: main() with fully mocked GitHub
# ---------------------------------------------------------------------------


class TestMainIntegration:
    """Integration-style tests that exercise main() more completely."""

    def _clean_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        for key in ["GITHUB_TOKEN", "INPUT_GITHUB_TOKEN", "GITHUB_REPOSITORY",
                    "PR_NUMBER", "INPUT_PR_NUMBER", "PCG_MODEL",
                    "PCG_WARN_THRESHOLD_USD", "PCG_BLOCK_THRESHOLD_USD",
                    "PCG_POST_COMMENT", "PCG_SECURITY_SCAN", "PCG_CONFIG_PATH",
                    "INPUT_CONFIG_PATH", "GITHUB_OUTPUT"]:
            monkeypatch.delenv(key, raising=False)

    def test_env_vars_used_when_no_cli_args(self,
                                            monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        monkeypatch.setenv("GITHUB_TOKEN", "ghp_env_token")
        monkeypatch.setenv("GITHUB_REPOSITORY", "env-owner/env-repo")
        monkeypatch.setenv("PR_NUMBER", "99")

        analysis = _make_analysis(repo="env-owner/env-repo", pr_number=99)
        security = _make_security()
        posted = _make_posted_comment()

        with patch("pr_cost_gate.cli.run", return_value=("OK", analysis, security, posted)) as mock_run:
            exit_code = main([])  # No CLI args

        assert exit_code == EXIT_OK
        call_kwargs = mock_run.call_args
        assert call_kwargs.kwargs.get("token") == "ghp_env_token" or \
               call_kwargs.args[0] == "ghp_env_token"

    def test_verbose_flag_passed_to_run(self,
                                        monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)

        analysis = _make_analysis()
        security = _make_security()
        posted = _make_posted_comment()

        with patch("pr_cost_gate.cli.run", return_value=("OK", analysis, security, posted)) as mock_run:
            main(["--token", "t", "--repo", "o/r", "--pr", "1", "--verbose"])

        call_kwargs = mock_run.call_args
        verbose_val = call_kwargs.kwargs.get("verbose")
        if verbose_val is None and call_kwargs.args:
            # Try positional arg at index 4
            try:
                verbose_val = call_kwargs.args[4]
            except IndexError:
                pass
        assert verbose_val is True

    def test_nonexistent_custom_config_returns_config_error(self,
                                                            monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        exit_code = main([
            "--token", "t", "--repo", "o/r", "--pr", "1",
            "--config", "/nonexistent/path/config.yml",
        ])
        assert exit_code == EXIT_CONFIG_ERROR
