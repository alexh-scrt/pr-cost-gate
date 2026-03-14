"""Unit tests for pr_cost_gate.analyzer.

Covers:
- Token counting via count_tokens()
- extract_diff_lines() in diff_only and full modes
- estimate_cost() against each model in the pricing table
- is_excluded() glob pattern matching
- FileAnalysis and PRAnalysisResult dataclass construction
- PRAnalyzer._analyze_file() logic including cap enforcement
- PRAnalyzer.analyze() with mocked PyGithub objects
- PRNotFoundError and AnalyzerError propagation
- analyze_pr() convenience wrapper
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Optional
from unittest.mock import MagicMock, patch

import pytest
import tiktoken

from pr_cost_gate.analyzer import (
    DEFAULT_ENCODING,
    MODEL_PRICING,
    OUTPUT_TOKEN_RATIO,
    AnalyzerError,
    FileAnalysis,
    PRAnalysisResult,
    PRAnalyzer,
    PRNotFoundError,
    analyze_pr,
    count_tokens,
    estimate_cost,
    extract_diff_lines,
    is_excluded,
)
from pr_cost_gate.config import GateConfig, ThresholdConfig, TokenConfig


# ---------------------------------------------------------------------------
# Fixtures and helpers
# ---------------------------------------------------------------------------


@pytest.fixture()
def default_config() -> GateConfig:
    """Return a default GateConfig."""
    return GateConfig()


@pytest.fixture()
def cl100k_encoding() -> tiktoken.Encoding:
    """Return the cl100k_base tiktoken encoding."""
    return tiktoken.get_encoding(DEFAULT_ENCODING)


SIMPLE_PATCH = """\
@@ -1,4 +1,5 @@
 def hello():
-    pass
+    return 'hello'
+
+# new comment
 context line
"""

BINARY_PATCH: Optional[str] = None


def _make_gh_file(
    filename: str = "src/main.py",
    patch: Optional[str] = SIMPLE_PATCH,
    additions: int = 3,
    deletions: int = 1,
    status: str = "modified",
) -> MagicMock:
    """Create a mock PyGithub File object."""
    f = MagicMock()
    f.filename = filename
    f.patch = patch
    f.additions = additions
    f.deletions = deletions
    f.status = status
    return f


def _make_pr(
    title: str = "Test PR",
    html_url: str = "https://github.com/owner/repo/pull/1",
    base_ref: str = "main",
    head_ref: str = "feature/test",
    files: Optional[list[MagicMock]] = None,
) -> MagicMock:
    """Create a mock PyGithub PullRequest object."""
    pr = MagicMock()
    pr.title = title
    pr.html_url = html_url
    pr.base.ref = base_ref
    pr.head.ref = head_ref
    pr.get_files.return_value = files or []
    return pr


def _make_github_client(pr: MagicMock, repo_name: str = "owner/repo") -> MagicMock:
    """Create a mock Github client that returns *pr* for any PR number."""
    gh = MagicMock()
    gh_repo = MagicMock()
    gh_repo.get_pull.return_value = pr
    gh.get_repo.return_value = gh_repo
    return gh


# ---------------------------------------------------------------------------
# count_tokens
# ---------------------------------------------------------------------------


class TestCountTokens:
    """Tests for the count_tokens() function."""

    def test_empty_string_returns_zero(self, cl100k_encoding: tiktoken.Encoding) -> None:
        assert count_tokens("", cl100k_encoding) == 0

    def test_single_word(self, cl100k_encoding: tiktoken.Encoding) -> None:
        count = count_tokens("hello", cl100k_encoding)
        assert count >= 1

    def test_longer_text_more_tokens(self, cl100k_encoding: tiktoken.Encoding) -> None:
        short_count = count_tokens("hi", cl100k_encoding)
        long_count = count_tokens("hello world this is a longer sentence", cl100k_encoding)
        assert long_count > short_count

    def test_whitespace_only_string(self, cl100k_encoding: tiktoken.Encoding) -> None:
        # Whitespace has tokens in tiktoken
        count = count_tokens("   \n   ", cl100k_encoding)
        assert isinstance(count, int)
        assert count >= 0

    def test_code_snippet(self, cl100k_encoding: tiktoken.Encoding) -> None:
        code = "def hello():\n    return 'world'\n"
        count = count_tokens(code, cl100k_encoding)
        assert count > 0

    def test_returns_integer(self, cl100k_encoding: tiktoken.Encoding) -> None:
        result = count_tokens("test", cl100k_encoding)
        assert isinstance(result, int)


# ---------------------------------------------------------------------------
# extract_diff_lines
# ---------------------------------------------------------------------------


class TestExtractDiffLines:
    """Tests for extract_diff_lines()."""

    def test_empty_patch_returns_empty(self) -> None:
        assert extract_diff_lines("", diff_only=True) == ""
        assert extract_diff_lines("", diff_only=False) == ""

    def test_none_equivalent_empty_patch(self) -> None:
        # Passing empty string (None guard is caller's responsibility)
        assert extract_diff_lines("", diff_only=True) == ""

    def test_diff_only_excludes_context(self) -> None:
        patch = "@@ -1,3 +1,3 @@\n context\n-removed\n+added\n"
        result = extract_diff_lines(patch, diff_only=True)
        assert "context" not in result
        assert "removed" in result
        assert "added" in result

    def test_diff_only_strips_plus_minus_prefix(self) -> None:
        patch = "@@ -1,2 +1,2 @@\n-old line\n+new line\n"
        result = extract_diff_lines(patch, diff_only=True)
        # Lines should not start with + or -
        for line in result.splitlines():
            assert not line.startswith("+"), f"Unexpected + in {line!r}"
            assert not line.startswith("-"), f"Unexpected - in {line!r}"

    def test_full_mode_includes_context(self) -> None:
        patch = "@@ -1,3 +1,3 @@\n context\n-removed\n+added\n"
        result = extract_diff_lines(patch, diff_only=False)
        assert "context" in result
        assert "removed" in result
        assert "added" in result

    def test_full_mode_excludes_hunk_headers(self) -> None:
        patch = "@@ -1,3 +1,3 @@\n context\n+added\n"
        result = extract_diff_lines(patch, diff_only=False)
        assert "@@" not in result

    def test_diff_only_excludes_hunk_markers(self) -> None:
        patch = "@@ -1,4 +1,5 @@\n-old\n+new\n unchanged\n"
        result = extract_diff_lines(patch, diff_only=True)
        assert "@@" not in result

    def test_diff_only_skips_file_header_lines(self) -> None:
        patch = "--- a/file.py\n+++ b/file.py\n@@ -1 +1 @@\n-old\n+new\n"
        result = extract_diff_lines(patch, diff_only=True)
        # +++ and --- should not be included
        assert "+++" not in result
        assert "---" not in result
        assert "old" in result
        assert "new" in result

    def test_multiline_patch(self) -> None:
        patch = (
            "@@ -1,5 +1,6 @@\n"
            " import os\n"
            "-x = 1\n"
            "+x = 2\n"
            "+y = 3\n"
            " print(x)\n"
        )
        diff_result = extract_diff_lines(patch, diff_only=True)
        lines = diff_result.splitlines()
        assert "x = 1" in lines
        assert "x = 2" in lines
        assert "y = 3" in lines
        assert "import os" not in lines


# ---------------------------------------------------------------------------
# estimate_cost
# ---------------------------------------------------------------------------


class TestEstimateCost:
    """Tests for estimate_cost()."""

    def test_zero_tokens_zero_cost(self) -> None:
        cost, output = estimate_cost(0, "gpt-4o")
        assert cost == pytest.approx(0.0)
        assert output == 0

    def test_returns_tuple(self) -> None:
        result = estimate_cost(1000, "gpt-4o")
        assert isinstance(result, tuple)
        assert len(result) == 2

    def test_cost_increases_with_tokens(self) -> None:
        cost_small, _ = estimate_cost(100, "gpt-4o")
        cost_large, _ = estimate_cost(10000, "gpt-4o")
        assert cost_large > cost_small

    def test_invalid_model_raises(self) -> None:
        with pytest.raises(AnalyzerError, match="not found in pricing table"):
            estimate_cost(1000, "gpt-99-ultra")

    def test_output_tokens_ratio(self) -> None:
        input_tokens = 1000
        _, output_tokens = estimate_cost(input_tokens, "gpt-4o")
        expected_output = int(input_tokens * OUTPUT_TOKEN_RATIO)
        assert output_tokens == expected_output

    def test_all_models_produce_positive_cost(self) -> None:
        for model in MODEL_PRICING:
            cost, _ = estimate_cost(10_000, model)
            assert cost > 0, f"Expected positive cost for model {model!r}"

    def test_gpt_4o_pricing(self) -> None:
        # 1M input tokens at $5/M + 200k output at $15/M = $5 + $3 = $8
        cost, output = estimate_cost(1_000_000, "gpt-4o")
        expected_output = int(1_000_000 * OUTPUT_TOKEN_RATIO)
        input_price, output_price = MODEL_PRICING["gpt-4o"]
        expected_cost = (
            1_000_000 / 1_000_000 * input_price
            + expected_output / 1_000_000 * output_price
        )
        assert cost == pytest.approx(expected_cost, rel=1e-6)
        assert output == expected_output

    def test_claude_3_opus_more_expensive_than_haiku(self) -> None:
        cost_opus, _ = estimate_cost(10_000, "claude-3-opus")
        cost_haiku, _ = estimate_cost(10_000, "claude-3-haiku")
        assert cost_opus > cost_haiku

    def test_custom_output_ratio(self) -> None:
        cost_low, out_low = estimate_cost(10_000, "gpt-4o", output_token_ratio=0.0)
        cost_high, out_high = estimate_cost(10_000, "gpt-4o", output_token_ratio=1.0)
        assert out_low == 0
        assert out_high == 10_000
        assert cost_high > cost_low

    def test_all_models_in_pricing_table(self) -> None:
        expected_models = {
            "gpt-4o",
            "gpt-4-turbo",
            "claude-3-5-sonnet",
            "claude-3-opus",
            "claude-3-haiku",
        }
        assert set(MODEL_PRICING.keys()) == expected_models


# ---------------------------------------------------------------------------
# is_excluded
# ---------------------------------------------------------------------------


class TestIsExcluded:
    """Tests for the is_excluded() function."""

    def test_no_patterns_never_excluded(self) -> None:
        assert is_excluded("src/main.py", []) is False

    def test_exact_match(self) -> None:
        assert is_excluded("src/main.py", ["src/main.py"]) is True

    def test_extension_glob(self) -> None:
        assert is_excluded("poetry.lock", ["**/*.lock"]) is True
        assert is_excluded("package-lock.json", ["**/*.lock"]) is False

    def test_lock_file_in_subdir(self) -> None:
        # Should match via basename check
        assert is_excluded("packages/foo/yarn.lock", ["**/*.lock"]) is True

    def test_vendor_directory(self) -> None:
        assert is_excluded("vendor/lib/something.py", ["**/vendor/**"]) is True
        assert is_excluded("src/vendor/lib/something.py", ["**/vendor/**"]) is True

    def test_non_matching_pattern(self) -> None:
        assert is_excluded("src/main.py", ["**/*.lock", "**/vendor/**"]) is False

    def test_node_modules(self) -> None:
        assert is_excluded("node_modules/lodash/index.js", ["**/node_modules/**"]) is True

    def test_min_js(self) -> None:
        assert is_excluded("dist/app.min.js", ["**/*.min.js"]) is True
        assert is_excluded("dist/app.js", ["**/*.min.js"]) is False

    def test_pycache(self) -> None:
        assert is_excluded("src/__pycache__/main.cpython-311.pyc", ["**/__pycache__/**"]) is True

    def test_multiple_patterns_first_match(self) -> None:
        patterns = ["**/*.lock", "**/vendor/**", "**/*.min.js"]
        assert is_excluded("vendor/x.py", patterns) is True
        assert is_excluded("app.min.js", patterns) is True
        assert is_excluded("src/core.py", patterns) is False

    def test_default_exclusions_from_config(self) -> None:
        """All default exclusion patterns should match their intended targets."""
        from pr_cost_gate.config import GateConfig
        patterns = GateConfig().exclusions.paths
        assert is_excluded("Pipfile.lock", patterns) is True
        assert is_excluded("src/api.py", patterns) is False


# ---------------------------------------------------------------------------
# FileAnalysis dataclass
# ---------------------------------------------------------------------------


class TestFileAnalysis:
    """Tests for the FileAnalysis dataclass."""

    def test_basic_construction(self) -> None:
        fa = FileAnalysis(
            filename="src/main.py",
            token_count=100,
            estimated_cost_usd=0.001,
        )
        assert fa.filename == "src/main.py"
        assert fa.token_count == 100
        assert fa.estimated_cost_usd == pytest.approx(0.001)
        assert fa.was_capped is False
        assert fa.patch == ""
        assert fa.additions == 0
        assert fa.deletions == 0
        assert fa.status == "modified"

    def test_capped_file(self) -> None:
        fa = FileAnalysis(
            filename="generated.py",
            token_count=100_000,
            estimated_cost_usd=1.0,
            was_capped=True,
        )
        assert fa.was_capped is True


# ---------------------------------------------------------------------------
# PRAnalysisResult dataclass
# ---------------------------------------------------------------------------


class TestPRAnalysisResult:
    """Tests for the PRAnalysisResult dataclass."""

    def test_default_construction(self) -> None:
        result = PRAnalysisResult(
            repo="owner/repo",
            pr_number=1,
            model="gpt-4o",
        )
        assert result.repo == "owner/repo"
        assert result.pr_number == 1
        assert result.model == "gpt-4o"
        assert result.files == []
        assert result.skipped_files == []
        assert result.total_tokens == 0
        assert result.estimated_cost_usd == 0.0
        assert result.any_capped is False


# ---------------------------------------------------------------------------
# PRAnalyzer._analyze_file
# ---------------------------------------------------------------------------


class TestPRAnalyzerAnalyzeFile:
    """Unit tests for PRAnalyzer._analyze_file()."""

    def _make_analyzer(self, config: Optional[GateConfig] = None) -> PRAnalyzer:
        gh = MagicMock()
        return PRAnalyzer(github_client=gh, config=config or GateConfig())

    def test_basic_file_analysis(self) -> None:
        analyzer = self._make_analyzer()
        fa = analyzer._analyze_file(
            filename="src/main.py",
            patch=SIMPLE_PATCH,
            additions=3,
            deletions=1,
            status="modified",
        )
        assert fa.filename == "src/main.py"
        assert fa.token_count > 0
        assert fa.estimated_cost_usd > 0
        assert fa.was_capped is False
        assert fa.additions == 3
        assert fa.deletions == 1
        assert fa.status == "modified"

    def test_binary_file_no_patch(self) -> None:
        analyzer = self._make_analyzer()
        fa = analyzer._analyze_file(
            filename="image.png",
            patch=None,
            additions=0,
            deletions=0,
            status="added",
        )
        assert fa.token_count == 0
        assert fa.estimated_cost_usd == pytest.approx(0.0)
        assert fa.patch == ""

    def test_token_cap_applied(self) -> None:
        from pr_cost_gate.config import GateConfig, TokenConfig
        config = GateConfig(tokens=TokenConfig(max_per_file=5, diff_only=True))
        analyzer = self._make_analyzer(config)
        big_patch = "+" + "word " * 1000 + "\n"
        fa = analyzer._analyze_file(
            filename="big.py",
            patch=big_patch,
            additions=1000,
            deletions=0,
            status="modified",
        )
        assert fa.token_count == 5
        assert fa.was_capped is True

    def test_diff_only_mode(self) -> None:
        config = GateConfig(tokens=TokenConfig(diff_only=True))
        analyzer = self._make_analyzer(config)
        patch = "@@ -1,2 +1,2 @@\n context line\n-old\n+new\n"
        fa = analyzer._analyze_file(
            filename="f.py", patch=patch, additions=1, deletions=1, status="modified"
        )
        # In diff_only mode the token count should be based on just the +/- lines
        assert fa.token_count > 0
        # context line tokens should NOT be counted
        encoding = tiktoken.get_encoding(DEFAULT_ENCODING)
        diff_text = extract_diff_lines(patch, diff_only=True)
        expected = count_tokens(diff_text, encoding)
        assert fa.token_count == expected

    def test_full_mode_includes_context(self) -> None:
        config = GateConfig(tokens=TokenConfig(diff_only=False))
        analyzer_full = self._make_analyzer(config)
        config_diff = GateConfig(tokens=TokenConfig(diff_only=True))
        analyzer_diff = self._make_analyzer(config_diff)

        patch = "@@ -1,3 +1,3 @@\n context line\n-old\n+new\n"
        fa_full = analyzer_full._analyze_file(
            "f.py", patch, additions=1, deletions=1, status="modified"
        )
        fa_diff = analyzer_diff._analyze_file(
            "f.py", patch, additions=1, deletions=1, status="modified"
        )
        # Full mode should have more tokens because it includes context
        assert fa_full.token_count >= fa_diff.token_count

    def test_model_affects_cost(self) -> None:
        """More expensive model should yield higher cost for same patch."""
        config_cheap = GateConfig(model="claude-3-haiku")
        config_expensive = GateConfig(model="claude-3-opus")
        analyzer_cheap = self._make_analyzer(config_cheap)
        analyzer_expensive = self._make_analyzer(config_expensive)

        fa_cheap = analyzer_cheap._analyze_file(
            "f.py", SIMPLE_PATCH, additions=3, deletions=1, status="modified"
        )
        fa_expensive = analyzer_expensive._analyze_file(
            "f.py", SIMPLE_PATCH, additions=3, deletions=1, status="modified"
        )
        assert fa_expensive.estimated_cost_usd > fa_cheap.estimated_cost_usd


# ---------------------------------------------------------------------------
# PRAnalyzer.analyze — integration-style with mocked GitHub
# ---------------------------------------------------------------------------


class TestPRAnalyzerAnalyze:
    """Tests for PRAnalyzer.analyze() with mocked PyGithub."""

    def test_empty_pr(self) -> None:
        pr = _make_pr(files=[])
        gh = _make_github_client(pr)
        analyzer = PRAnalyzer(github_client=gh, config=GateConfig())
        result = analyzer.analyze(repo="owner/repo", pr_number=1)
        assert result.total_tokens == 0
        assert result.estimated_cost_usd == pytest.approx(0.0)
        assert result.files == []
        assert result.skipped_files == []

    def test_single_file_pr(self) -> None:
        files = [_make_gh_file("src/main.py", SIMPLE_PATCH, 3, 1, "modified")]
        pr = _make_pr(files=files)
        gh = _make_github_client(pr)
        analyzer = PRAnalyzer(github_client=gh, config=GateConfig())
        result = analyzer.analyze(repo="owner/repo", pr_number=1)
        assert len(result.files) == 1
        assert result.files[0].filename == "src/main.py"
        assert result.total_tokens > 0
        assert result.estimated_cost_usd > 0

    def test_multiple_files_aggregate(self) -> None:
        files = [
            _make_gh_file("src/a.py", SIMPLE_PATCH, 3, 1, "modified"),
            _make_gh_file("src/b.py", SIMPLE_PATCH, 2, 0, "added"),
        ]
        pr = _make_pr(files=files)
        gh = _make_github_client(pr)
        analyzer = PRAnalyzer(github_client=gh, config=GateConfig())
        result = analyzer.analyze(repo="owner/repo", pr_number=1)
        assert len(result.files) == 2
        expected_tokens = sum(f.token_count for f in result.files)
        assert result.total_tokens == expected_tokens

    def test_excluded_files_go_to_skipped(self) -> None:
        from pr_cost_gate.config import ExclusionsConfig
        config = GateConfig(exclusions=ExclusionsConfig(paths=["**/*.lock"]))
        files = [
            _make_gh_file("poetry.lock", "+locked\n", 1, 0, "modified"),
            _make_gh_file("src/main.py", SIMPLE_PATCH, 3, 1, "modified"),
        ]
        pr = _make_pr(files=files)
        gh = _make_github_client(pr)
        analyzer = PRAnalyzer(github_client=gh, config=config)
        result = analyzer.analyze(repo="owner/repo", pr_number=1)
        assert "poetry.lock" in result.skipped_files
        assert len(result.files) == 1
        assert result.files[0].filename == "src/main.py"

    def test_pr_metadata_captured(self) -> None:
        pr = _make_pr(
            title="My Feature",
            html_url="https://github.com/owner/repo/pull/42",
            base_ref="main",
            head_ref="feature/my-feature",
            files=[],
        )
        gh = _make_github_client(pr)
        analyzer = PRAnalyzer(github_client=gh, config=GateConfig())
        result = analyzer.analyze(repo="owner/repo", pr_number=42)
        assert result.pr_title == "My Feature"
        assert result.pr_url == "https://github.com/owner/repo/pull/42"
        assert result.base_branch == "main"
        assert result.head_branch == "feature/my-feature"
        assert result.pr_number == 42
        assert result.repo == "owner/repo"

    def test_any_capped_true_when_file_capped(self) -> None:
        from pr_cost_gate.config import TokenConfig
        config = GateConfig(tokens=TokenConfig(max_per_file=1, diff_only=True))
        files = [_make_gh_file("big.py", "+" + "word " * 100, 100, 0, "added")]
        pr = _make_pr(files=files)
        gh = _make_github_client(pr)
        analyzer = PRAnalyzer(github_client=gh, config=config)
        result = analyzer.analyze(repo="owner/repo", pr_number=1)
        assert result.any_capped is True

    def test_any_capped_false_when_no_file_capped(self) -> None:
        files = [_make_gh_file("small.py", "+x = 1\n", 1, 0, "modified")]
        pr = _make_pr(files=files)
        gh = _make_github_client(pr)
        analyzer = PRAnalyzer(github_client=gh, config=GateConfig())
        result = analyzer.analyze(repo="owner/repo", pr_number=1)
        assert result.any_capped is False

    def test_output_tokens_estimated(self) -> None:
        files = [_make_gh_file("src/main.py", SIMPLE_PATCH, 3, 1, "modified")]
        pr = _make_pr(files=files)
        gh = _make_github_client(pr)
        analyzer = PRAnalyzer(github_client=gh, config=GateConfig())
        result = analyzer.analyze(repo="owner/repo", pr_number=1)
        expected_output = int(result.total_tokens * OUTPUT_TOKEN_RATIO)
        assert result.output_tokens == expected_output

    def test_cost_consistent_with_per_file_sum(self) -> None:
        """Total cost should be computed from total_tokens, not summed per file."""
        files = [
            _make_gh_file("a.py", SIMPLE_PATCH, 3, 1, "modified"),
            _make_gh_file("b.py", SIMPLE_PATCH, 2, 0, "added"),
        ]
        pr = _make_pr(files=files)
        gh = _make_github_client(pr)
        analyzer = PRAnalyzer(github_client=gh, config=GateConfig())
        result = analyzer.analyze(repo="owner/repo", pr_number=1)
        expected_cost, _ = estimate_cost(result.total_tokens, result.model)
        assert result.estimated_cost_usd == pytest.approx(expected_cost, rel=1e-6)

    def test_model_passed_to_result(self) -> None:
        config = GateConfig(model="claude-3-opus")
        pr = _make_pr(files=[])
        gh = _make_github_client(pr)
        analyzer = PRAnalyzer(github_client=gh, config=config)
        result = analyzer.analyze(repo="owner/repo", pr_number=1)
        assert result.model == "claude-3-opus"

    def test_input_tokens_equals_total_tokens(self) -> None:
        files = [_make_gh_file("x.py", SIMPLE_PATCH, 3, 1, "modified")]
        pr = _make_pr(files=files)
        gh = _make_github_client(pr)
        analyzer = PRAnalyzer(github_client=gh, config=GateConfig())
        result = analyzer.analyze(repo="owner/repo", pr_number=1)
        assert result.input_tokens == result.total_tokens


# ---------------------------------------------------------------------------
# PRAnalyzer error handling
# ---------------------------------------------------------------------------


class TestPRAnalyzerErrors:
    """Test error propagation in PRAnalyzer."""

    def test_repo_not_found_raises_analyzer_error(self) -> None:
        gh = MagicMock()
        gh.get_repo.side_effect = Exception("Not Found")
        analyzer = PRAnalyzer(github_client=gh, config=GateConfig())
        with pytest.raises(AnalyzerError, match="Cannot access repository"):
            analyzer.analyze(repo="bad/repo", pr_number=1)

    def test_pr_not_found_raises_pr_not_found_error(self) -> None:
        gh = MagicMock()
        gh_repo = MagicMock()
        gh_repo.get_pull.side_effect = Exception("PR not found")
        gh.get_repo.return_value = gh_repo
        analyzer = PRAnalyzer(github_client=gh, config=GateConfig())
        with pytest.raises(PRNotFoundError):
            analyzer.analyze(repo="owner/repo", pr_number=9999)

    def test_get_files_error_raises_analyzer_error(self) -> None:
        gh = MagicMock()
        gh_repo = MagicMock()
        pr = MagicMock()
        pr.title = "Test"
        pr.html_url = "https://example.com"
        pr.base.ref = "main"
        pr.head.ref = "feature"
        pr.get_files.side_effect = Exception("API rate limit")
        gh_repo.get_pull.return_value = pr
        gh.get_repo.return_value = gh_repo
        analyzer = PRAnalyzer(github_client=gh, config=GateConfig())
        with pytest.raises(AnalyzerError, match="Cannot retrieve files"):
            analyzer.analyze(repo="owner/repo", pr_number=1)

    def test_pr_not_found_error_is_analyzer_error(self) -> None:
        assert issubclass(PRNotFoundError, AnalyzerError)

    def test_analyzer_error_is_runtime_error(self) -> None:
        assert issubclass(AnalyzerError, RuntimeError)


# ---------------------------------------------------------------------------
# analyze_pr convenience wrapper
# ---------------------------------------------------------------------------


class TestAnalyzePr:
    """Tests for the analyze_pr() convenience function."""

    def test_returns_pr_analysis_result(self) -> None:
        files = [_make_gh_file("src/main.py", SIMPLE_PATCH, 3, 1, "modified")]
        pr = _make_pr(files=files)

        with patch("pr_cost_gate.analyzer.Github") as mock_github_cls:
            mock_gh_instance = MagicMock()
            gh_repo = MagicMock()
            gh_repo.get_pull.return_value = pr
            mock_gh_instance.get_repo.return_value = gh_repo
            mock_github_cls.return_value = mock_gh_instance

            result = analyze_pr(
                token="ghp_test",
                repo="owner/repo",
                pr_number=1,
            )

        assert isinstance(result, PRAnalysisResult)
        assert result.repo == "owner/repo"
        assert result.pr_number == 1

    def test_uses_default_config_when_none(self) -> None:
        pr = _make_pr(files=[])

        with patch("pr_cost_gate.analyzer.Github") as mock_github_cls:
            mock_gh_instance = MagicMock()
            gh_repo = MagicMock()
            gh_repo.get_pull.return_value = pr
            mock_gh_instance.get_repo.return_value = gh_repo
            mock_github_cls.return_value = mock_gh_instance

            result = analyze_pr(token="ghp_test", repo="owner/repo", pr_number=1)

        assert result.model == "gpt-4o"

    def test_custom_config_applied(self) -> None:
        pr = _make_pr(files=[])
        config = GateConfig(model="claude-3-haiku")

        with patch("pr_cost_gate.analyzer.Github") as mock_github_cls:
            mock_gh_instance = MagicMock()
            gh_repo = MagicMock()
            gh_repo.get_pull.return_value = pr
            mock_gh_instance.get_repo.return_value = gh_repo
            mock_github_cls.return_value = mock_gh_instance

            result = analyze_pr(
                token="ghp_test",
                repo="owner/repo",
                pr_number=1,
                config=config,
            )

        assert result.model == "claude-3-haiku"

    def test_github_client_created_with_token(self) -> None:
        pr = _make_pr(files=[])

        with patch("pr_cost_gate.analyzer.Github") as mock_github_cls:
            mock_gh_instance = MagicMock()
            gh_repo = MagicMock()
            gh_repo.get_pull.return_value = pr
            mock_gh_instance.get_repo.return_value = gh_repo
            mock_github_cls.return_value = mock_gh_instance

            analyze_pr(token="ghp_mytoken", repo="owner/repo", pr_number=1)

            mock_github_cls.assert_called_once_with("ghp_mytoken")


# ---------------------------------------------------------------------------
# Encoding lazy loading
# ---------------------------------------------------------------------------


class TestEncodingLazyLoad:
    """Test that the tiktoken encoding is loaded lazily and cached."""

    def test_encoding_loaded_on_first_access(self) -> None:
        gh = MagicMock()
        config = GateConfig(model="gpt-4o")
        analyzer = PRAnalyzer(github_client=gh, config=config)
        assert analyzer._encoding is None
        enc = analyzer.encoding
        assert enc is not None
        assert analyzer._encoding is enc

    def test_encoding_cached_on_subsequent_access(self) -> None:
        gh = MagicMock()
        config = GateConfig(model="gpt-4o")
        analyzer = PRAnalyzer(github_client=gh, config=config)
        enc1 = analyzer.encoding
        enc2 = analyzer.encoding
        assert enc1 is enc2

    def test_different_models_have_different_encodings(self) -> None:
        gh = MagicMock()
        analyzer_4o = PRAnalyzer(github_client=gh, config=GateConfig(model="gpt-4o"))
        analyzer_claude = PRAnalyzer(
            github_client=gh, config=GateConfig(model="claude-3-opus")
        )
        # gpt-4o uses o200k_base, claude uses cl100k_base
        enc_4o = analyzer_4o.encoding
        enc_claude = analyzer_claude.encoding
        assert enc_4o.name != enc_claude.name
