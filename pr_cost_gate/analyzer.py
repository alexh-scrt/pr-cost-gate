"""Token counting and cost estimation for GitHub PR diffs.

This module fetches pull request diffs via PyGithub, counts tokens per changed
file using tiktoken, and estimates AI review costs against a built-in pricing
table for popular models.

Typical usage::

    from github import Github
    from pr_cost_gate.analyzer import PRAnalyzer
    from pr_cost_gate.config import GateConfig

    config = GateConfig()
    gh = Github(token="ghp_...")
    analyzer = PRAnalyzer(github_client=gh, config=config)
    result = analyzer.analyze(repo="owner/repo", pr_number=42)
    print(result.total_tokens)
    print(result.estimated_cost_usd)
"""

from __future__ import annotations

import fnmatch
from dataclasses import dataclass, field
from typing import Optional

import tiktoken
from github import Github
from github.PullRequest import PullRequest
from github.Repository import Repository

from pr_cost_gate.config import GateConfig

# ---------------------------------------------------------------------------
# Model pricing table
# ---------------------------------------------------------------------------

#: Pricing per 1 million tokens in USD.
#: Each entry is (input_cost_per_1m, output_cost_per_1m).
#: For diff analysis we only send tokens as "input"; output is estimated as
#: a small fraction (20%) of input tokens for the review response.
MODEL_PRICING: dict[str, tuple[float, float]] = {
    "gpt-4o": (5.00, 15.00),
    "gpt-4-turbo": (10.00, 30.00),
    "claude-3-5-sonnet": (3.00, 15.00),
    "claude-3-opus": (15.00, 75.00),
    "claude-3-haiku": (0.25, 1.25),
}

#: Fraction of input tokens assumed to be generated as output (review response).
OUTPUT_TOKEN_RATIO: float = 0.20

#: Tiktoken encoding used for all models.
#: cl100k_base is accurate for GPT-4 family; we use it as a reasonable
#: approximation for Claude models as well.
DEFAULT_ENCODING: str = "cl100k_base"

#: Map model identifiers to tiktoken encoding names.
MODEL_ENCODING_MAP: dict[str, str] = {
    "gpt-4o": "o200k_base",
    "gpt-4-turbo": "cl100k_base",
    "claude-3-5-sonnet": "cl100k_base",
    "claude-3-opus": "cl100k_base",
    "claude-3-haiku": "cl100k_base",
}


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class AnalyzerError(RuntimeError):
    """Raised when the PR analyzer encounters an unrecoverable error."""


class PRNotFoundError(AnalyzerError):
    """Raised when the specified pull request cannot be found."""


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class FileAnalysis:
    """Token count and cost breakdown for a single changed file.

    Attributes:
        filename: Path of the file as reported by the GitHub API.
        token_count: Number of tokens in the analysed diff content.
        estimated_cost_usd: Estimated AI review cost for this file in USD.
        was_capped: ``True`` if the token count hit ``tokens.max_per_file``.
        patch: The raw unified diff patch string (may be empty for binary files).
        additions: Number of added lines.
        deletions: Number of deleted lines.
        status: File change status (``'added'``, ``'modified'``, ``'removed'``, etc.).
    """

    filename: str
    token_count: int
    estimated_cost_usd: float
    was_capped: bool = False
    patch: str = ""
    additions: int = 0
    deletions: int = 0
    status: str = "modified"


@dataclass
class PRAnalysisResult:
    """Aggregated analysis result for an entire pull request.

    Attributes:
        repo: Repository name in ``owner/name`` format.
        pr_number: Pull request number.
        model: AI model used for cost estimation.
        files: Per-file analysis results (excluding skipped files).
        skipped_files: Filenames excluded by path exclusion patterns.
        total_tokens: Sum of token counts across all analysed files.
        estimated_cost_usd: Total estimated AI review cost in USD.
        input_tokens: Tokens counted as "input" to the model.
        output_tokens: Estimated output tokens (``input * OUTPUT_TOKEN_RATIO``).
        any_capped: ``True`` if at least one file's token count was capped.
        pr_title: Title of the pull request.
        pr_url: HTML URL of the pull request.
        base_branch: Base branch name.
        head_branch: Head branch name.
    """

    repo: str
    pr_number: int
    model: str
    files: list[FileAnalysis] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)
    total_tokens: int = 0
    estimated_cost_usd: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    any_capped: bool = False
    pr_title: str = ""
    pr_url: str = ""
    base_branch: str = ""
    head_branch: str = ""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _get_encoding(model: str) -> tiktoken.Encoding:
    """Return a tiktoken Encoding for *model*.

    Falls back to :data:`DEFAULT_ENCODING` if the model is not recognised.

    Args:
        model: Model identifier string.

    Returns:
        A :class:`tiktoken.Encoding` instance.
    """
    encoding_name = MODEL_ENCODING_MAP.get(model, DEFAULT_ENCODING)
    try:
        return tiktoken.get_encoding(encoding_name)
    except Exception:  # pragma: no cover — tiktoken internal error
        return tiktoken.get_encoding(DEFAULT_ENCODING)


def count_tokens(text: str, encoding: tiktoken.Encoding) -> int:
    """Count the number of tokens in *text* using *encoding*.

    Args:
        text: String to tokenise.
        encoding: Pre-loaded tiktoken encoding.

    Returns:
        Integer token count.  Returns ``0`` for empty strings.
    """
    if not text:
        return 0
    return len(encoding.encode(text))


def extract_diff_lines(patch: str, diff_only: bool) -> str:
    """Extract relevant lines from a unified diff patch.

    Args:
        patch: Raw unified diff string (as returned by the GitHub API).
        diff_only: When ``True``, return only added (``+``) and removed (``-``)
            lines stripped of their prefix character.  When ``False``, return
            all lines (including context lines starting with a space).

    Returns:
        A single string containing the selected lines joined by newlines.
    """
    if not patch:
        return ""

    lines = patch.splitlines()
    if not diff_only:
        # Include everything except hunk headers (@@…@@)
        selected = [
            line for line in lines
            if not line.startswith("@@") and not line.startswith("\\")  # \ No newline
        ]
        return "\n".join(selected)

    # diff_only=True: only +/- lines, strip the leading +/-
    selected_diff_only = []
    for line in lines:
        if line.startswith("+") and not line.startswith("+++"):
            selected_diff_only.append(line[1:])
        elif line.startswith("-") and not line.startswith("---"):
            selected_diff_only.append(line[1:])
    return "\n".join(selected_diff_only)


def estimate_cost(
    input_tokens: int,
    model: str,
    output_token_ratio: float = OUTPUT_TOKEN_RATIO,
) -> tuple[float, int]:
    """Estimate AI review cost for a given token count and model.

    The output token count is estimated as ``input_tokens * output_token_ratio``
    to account for the model's review response.

    Args:
        input_tokens: Number of input tokens.
        model: Model identifier from :data:`MODEL_PRICING`.
        output_token_ratio: Fraction of input tokens assumed to be output.

    Returns:
        A tuple ``(cost_usd, estimated_output_tokens)``.

    Raises:
        AnalyzerError: If *model* is not in the pricing table.
    """
    if model not in MODEL_PRICING:
        raise AnalyzerError(
            f"Model {model!r} not found in pricing table. "
            f"Supported models: {sorted(MODEL_PRICING)}"
        )
    input_price_per_1m, output_price_per_1m = MODEL_PRICING[model]
    output_tokens = int(input_tokens * output_token_ratio)
    cost = (
        input_tokens / 1_000_000 * input_price_per_1m
        + output_tokens / 1_000_000 * output_price_per_1m
    )
    return cost, output_tokens


def is_excluded(filename: str, exclusion_patterns: list[str]) -> bool:
    """Return ``True`` if *filename* matches any of the exclusion glob patterns.

    Patterns follow Unix shell glob conventions (``fnmatch``) applied to the
    full path.  ``**`` is expanded to match path separators.

    Args:
        filename: File path as reported by the GitHub API.
        exclusion_patterns: List of glob patterns to match against.

    Returns:
        ``True`` if the file should be excluded from analysis.
    """
    for pattern in exclusion_patterns:
        # Normalise double-star globs by replacing with a single-level match
        # for each path component since fnmatch doesn't support ** natively.
        if fnmatch.fnmatch(filename, pattern):
            return True
        # Also try matching the basename alone for patterns like "*.lock"
        basename = filename.split("/")[-1]
        if fnmatch.fnmatch(basename, pattern):
            return True
        # Handle **/ prefix patterns by matching any path depth
        if "**/" in pattern:
            # Strip **/ prefixes and try matching the path directly
            stripped = pattern
            while stripped.startswith("**/"):
                stripped = stripped[3:]
            if fnmatch.fnmatch(filename, stripped):
                return True
            # Also try matching any suffix of the path components
            parts = filename.split("/")
            for i in range(len(parts)):
                subpath = "/".join(parts[i:])
                if fnmatch.fnmatch(subpath, stripped):
                    return True
        # Handle patterns ending with /**
        if pattern.endswith("/**"):
            prefix = pattern[:-3]
            # Strip leading **/ from prefix
            while prefix.startswith("**/"):
                prefix = prefix[3:]
            if filename.startswith(prefix + "/") or filename == prefix:
                return True
    return False


# ---------------------------------------------------------------------------
# Main analyzer class
# ---------------------------------------------------------------------------


class PRAnalyzer:
    """Fetches a GitHub PR diff and produces a per-file cost estimate.

    Args:
        github_client: An authenticated :class:`github.Github` instance.
        config: :class:`~pr_cost_gate.config.GateConfig` with model and
            token settings.
    """

    def __init__(self, github_client: Github, config: GateConfig) -> None:
        self._gh = github_client
        self._config = config
        self._encoding: Optional[tiktoken.Encoding] = None

    @property
    def encoding(self) -> tiktoken.Encoding:
        """Lazily-loaded tiktoken encoding for the configured model."""
        if self._encoding is None:
            self._encoding = _get_encoding(self._config.model)
        return self._encoding

    def _get_pr(self, repo: str, pr_number: int) -> tuple[Repository, PullRequest]:
        """Fetch the repository and pull request objects from GitHub.

        Args:
            repo: Repository in ``owner/name`` format.
            pr_number: Pull request number.

        Returns:
            Tuple of ``(repository, pull_request)``.

        Raises:
            PRNotFoundError: If the PR or repository cannot be found.
            AnalyzerError: On unexpected GitHub API errors.
        """
        try:
            gh_repo = self._gh.get_repo(repo)
        except Exception as exc:
            raise AnalyzerError(f"Cannot access repository {repo!r}: {exc}") from exc

        try:
            pr = gh_repo.get_pull(pr_number)
        except Exception as exc:
            raise PRNotFoundError(
                f"Pull request #{pr_number} not found in {repo!r}: {exc}"
            ) from exc

        return gh_repo, pr

    def _analyze_file(
        self,
        filename: str,
        patch: Optional[str],
        additions: int,
        deletions: int,
        status: str,
    ) -> FileAnalysis:
        """Analyse a single changed file and return its token/cost breakdown.

        Args:
            filename: File path as reported by the GitHub API.
            patch: Raw unified diff patch string, or ``None`` for binary files.
            additions: Number of added lines.
            deletions: Number of deleted lines.
            status: Change status string (e.g. ``'added'``, ``'modified'``).

        Returns:
            A populated :class:`FileAnalysis` instance.
        """
        raw_patch = patch or ""
        diff_text = extract_diff_lines(raw_patch, self._config.tokens.diff_only)
        raw_count = count_tokens(diff_text, self.encoding)

        was_capped = False
        token_count = raw_count
        if token_count > self._config.tokens.max_per_file:
            token_count = self._config.tokens.max_per_file
            was_capped = True

        cost, _ = estimate_cost(token_count, self._config.model)

        return FileAnalysis(
            filename=filename,
            token_count=token_count,
            estimated_cost_usd=cost,
            was_capped=was_capped,
            patch=raw_patch,
            additions=additions,
            deletions=deletions,
            status=status,
        )

    def analyze(self, repo: str, pr_number: int) -> PRAnalysisResult:
        """Fetch a pull request and produce a full cost analysis.

        Args:
            repo: Repository in ``owner/name`` format (e.g. ``'octocat/Hello-World'``).
            pr_number: The pull request number to analyse.

        Returns:
            A :class:`PRAnalysisResult` containing per-file breakdowns and totals.

        Raises:
            PRNotFoundError: If the PR cannot be found.
            AnalyzerError: On GitHub API errors or unsupported model.
        """
        _gh_repo, pr = self._get_pr(repo, pr_number)

        result = PRAnalysisResult(
            repo=repo,
            pr_number=pr_number,
            model=self._config.model,
            pr_title=pr.title,
            pr_url=pr.html_url,
            base_branch=pr.base.ref,
            head_branch=pr.head.ref,
        )

        exclusion_patterns = self._config.exclusions.paths

        try:
            changed_files = list(pr.get_files())
        except Exception as exc:
            raise AnalyzerError(
                f"Cannot retrieve files for PR #{pr_number} in {repo!r}: {exc}"
            ) from exc

        for gh_file in changed_files:
            filename: str = gh_file.filename

            if is_excluded(filename, exclusion_patterns):
                result.skipped_files.append(filename)
                continue

            file_analysis = self._analyze_file(
                filename=filename,
                patch=gh_file.patch if hasattr(gh_file, "patch") else None,
                additions=gh_file.additions,
                deletions=gh_file.deletions,
                status=gh_file.status,
            )
            result.files.append(file_analysis)

        # Aggregate totals
        result.total_tokens = sum(f.token_count for f in result.files)
        result.any_capped = any(f.was_capped for f in result.files)
        result.input_tokens = result.total_tokens
        result.output_tokens = int(result.total_tokens * OUTPUT_TOKEN_RATIO)

        total_cost, _ = estimate_cost(result.total_tokens, self._config.model)
        result.estimated_cost_usd = total_cost

        return result


# ---------------------------------------------------------------------------
# Convenience function
# ---------------------------------------------------------------------------


def analyze_pr(
    token: str,
    repo: str,
    pr_number: int,
    config: Optional[GateConfig] = None,
) -> PRAnalysisResult:
    """High-level convenience wrapper for analysing a pull request.

    Creates a :class:`github.Github` client from *token*, instantiates a
    :class:`PRAnalyzer`, and returns the analysis result.

    Args:
        token: GitHub personal access token or ``GITHUB_TOKEN``.
        repo: Repository in ``owner/name`` format.
        pr_number: Pull request number to analyse.
        config: Configuration to use.  Defaults to :class:`GateConfig` with
            all defaults when ``None``.

    Returns:
        A :class:`PRAnalysisResult` with per-file breakdowns and totals.

    Raises:
        PRNotFoundError: If the PR cannot be found.
        AnalyzerError: On GitHub API errors.
    """
    if config is None:
        config = GateConfig()
    gh = Github(token)
    analyzer = PRAnalyzer(github_client=gh, config=config)
    return analyzer.analyze(repo=repo, pr_number=pr_number)
