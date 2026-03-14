"""CLI entry point for pr_cost_gate.

Orchestrates the analyzer, security scanner, and comment poster via
command-line arguments and environment variables.  Sets the process
exit code based on the configured cost thresholds and security findings.

Typical usage::

    # As a CLI tool
    pr-cost-gate --token ghp_... --repo owner/repo --pr 42

    # As a GitHub Action (via environment variables)
    pr-cost-gate

Exit codes:
    0  — OK or WARN (workflow continues)
    1  — BLOCK (workflow should stop) or unrecoverable error
    2  — Configuration or argument error
"""

from __future__ import annotations

import argparse
import os
import sys
import traceback
from typing import Optional

from pr_cost_gate.analyzer import AnalyzerError, PRAnalysisResult, PRNotFoundError, analyze_pr
from pr_cost_gate.comment import (
    CommentError,
    PostedComment,
    build_and_post_comment,
    determine_risk_level,
)
from pr_cost_gate.config import (
    SUPPORTED_MODELS,
    ConfigError,
    ConfigFileNotFoundError,
    GateConfig,
    load_config,
    load_config_from_env,
)
from pr_cost_gate.security import SecurityScanResult, scan_files

# ---------------------------------------------------------------------------
# Exit codes
# ---------------------------------------------------------------------------

EXIT_OK: int = 0
EXIT_BLOCK: int = 1
EXIT_CONFIG_ERROR: int = 2


# ---------------------------------------------------------------------------
# Output helpers
# ---------------------------------------------------------------------------


def _print_info(message: str) -> None:
    """Print an informational message to stdout."""
    print(f"[pr-cost-gate] {message}", flush=True)


def _print_warn(message: str) -> None:
    """Print a warning message to stderr."""
    print(f"[pr-cost-gate] WARNING: {message}", file=sys.stderr, flush=True)


def _print_error(message: str) -> None:
    """Print an error message to stderr."""
    print(f"[pr-cost-gate] ERROR: {message}", file=sys.stderr, flush=True)


def _set_github_output(key: str, value: str) -> None:
    """Write a key=value pair to the GitHub Actions output file if available.

    When running outside GitHub Actions (no GITHUB_OUTPUT env var), this
    is a no-op.

    Args:
        key: Output variable name.
        value: Output variable value.
    """
    github_output = os.environ.get("GITHUB_OUTPUT")
    if github_output:
        try:
            with open(github_output, "a", encoding="utf-8") as fh:
                fh.write(f"{key}={value}\n")
        except OSError as exc:
            _print_warn(f"Cannot write to GITHUB_OUTPUT ({github_output}): {exc}")


def _set_github_action_outputs(
    analysis: PRAnalysisResult,
    security: SecurityScanResult,
    risk_level: str,
    posted_comment: Optional[PostedComment],
) -> None:
    """Write all action outputs to the GitHub Actions output file.

    Args:
        analysis: PR analysis result.
        security: Security scan result.
        risk_level: Computed risk level string.
        posted_comment: The posted comment, or ``None`` if not posted.
    """
    _set_github_output("total_tokens", str(analysis.total_tokens))
    _set_github_output("estimated_cost_usd", f"{analysis.estimated_cost_usd:.6f}")
    _set_github_output("risk_level", risk_level)
    _set_github_output("security_findings", str(security.total_count))
    if posted_comment is not None:
        _set_github_output("comment_url", posted_comment.comment_url)
    else:
        _set_github_output("comment_url", "")


# ---------------------------------------------------------------------------
# Argument parser
# ---------------------------------------------------------------------------


def _build_parser() -> argparse.ArgumentParser:
    """Build and return the CLI argument parser.

    Returns:
        A configured :class:`argparse.ArgumentParser` instance.
    """
    parser = argparse.ArgumentParser(
        prog="pr-cost-gate",
        description=(
            "Analyze a GitHub pull request for estimated AI review costs and "
            "security risks. Posts a structured summary comment to the PR and "
            "exits with a non-zero status when configured thresholds are exceeded."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=textwrap.dedent("""\
            Environment variables (override CLI flags):
              GITHUB_TOKEN            GitHub API token (required if --token not set)
              GITHUB_REPOSITORY       Repository in owner/name format
              PR_NUMBER               Pull request number
              PCG_MODEL               AI model for cost estimation
              PCG_WARN_THRESHOLD_USD  Cost threshold for WARN level
              PCG_BLOCK_THRESHOLD_USD Cost threshold for BLOCK level
              PCG_CONFIG_PATH         Path to .pr_cost_gate.yml
              PCG_POST_COMMENT        'true'/'false' — whether to post comment
              PCG_SECURITY_SCAN       'true'/'false' — whether to run security scan

            Exit codes:
              0  OK or WARN — workflow continues
              1  BLOCK — workflow is halted
              2  Configuration or argument error

            Examples:
              pr-cost-gate --token ghp_abc --repo owner/repo --pr 42
              pr-cost-gate --token ghp_abc --repo owner/repo --pr 42 --model claude-3-opus
              pr-cost-gate --token ghp_abc --repo owner/repo --pr 42 --no-comment
        """),
    )

    auth_group = parser.add_argument_group("Authentication")
    auth_group.add_argument(
        "--token",
        metavar="TOKEN",
        default=None,
        help=(
            "GitHub personal access token or GITHUB_TOKEN. "
            "Falls back to the GITHUB_TOKEN environment variable."
        ),
    )

    pr_group = parser.add_argument_group("Pull Request")
    pr_group.add_argument(
        "--repo",
        metavar="OWNER/NAME",
        default=None,
        help=(
            "Repository in owner/name format (e.g. 'octocat/Hello-World'). "
            "Falls back to GITHUB_REPOSITORY environment variable."
        ),
    )
    pr_group.add_argument(
        "--pr",
        metavar="NUMBER",
        type=int,
        default=None,
        dest="pr_number",
        help=(
            "Pull request number to analyse. "
            "Falls back to PR_NUMBER environment variable."
        ),
    )

    cost_group = parser.add_argument_group("Cost Estimation")
    cost_group.add_argument(
        "--model",
        metavar="MODEL",
        default=None,
        choices=sorted(SUPPORTED_MODELS),
        help=(
            "AI model for cost estimation. "
            f"One of: {', '.join(sorted(SUPPORTED_MODELS))}. "
            "Overrides the config file setting."
        ),
    )
    cost_group.add_argument(
        "--warn-threshold",
        metavar="USD",
        type=float,
        default=None,
        dest="warn_threshold_usd",
        help=(
            "Estimated cost in USD above which a WARN label is added. "
            "Set to 0 to disable warnings. Overrides the config file setting."
        ),
    )
    cost_group.add_argument(
        "--block-threshold",
        metavar="USD",
        type=float,
        default=None,
        dest="block_threshold_usd",
        help=(
            "Estimated cost in USD above which the tool exits with status 1, "
            "blocking downstream AI review steps. "
            "Set to 0 to disable blocking. Overrides the config file setting."
        ),
    )

    output_group = parser.add_argument_group("Output")
    output_group.add_argument(
        "--no-comment",
        action="store_true",
        default=False,
        help="Skip posting the summary comment to the pull request.",
    )
    output_group.add_argument(
        "--no-security",
        action="store_true",
        default=False,
        help="Skip the security risk pattern scan.",
    )
    output_group.add_argument(
        "--config",
        metavar="PATH",
        default=None,
        dest="config_path",
        help=(
            "Path to the .pr_cost_gate.yml configuration file. "
            "Falls back to PCG_CONFIG_PATH or '.pr_cost_gate.yml' in the current directory."
        ),
    )
    output_group.add_argument(
        "--verbose",
        "-v",
        action="store_true",
        default=False,
        help="Enable verbose output (print per-file token counts and costs).",
    )
    output_group.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {_get_version()}",
    )

    return parser


try:
    import textwrap as textwrap
except ImportError:
    import textwrap  # type: ignore[no-redef]


def _get_version() -> str:
    """Return the package version string."""
    try:
        from pr_cost_gate import __version__
        return __version__
    except ImportError:
        return "unknown"


# ---------------------------------------------------------------------------
# Resolution helpers
# ---------------------------------------------------------------------------


def _resolve_token(args: argparse.Namespace) -> Optional[str]:
    """Resolve the GitHub token from CLI args or environment variables.

    Args:
        args: Parsed command-line arguments.

    Returns:
        The token string, or ``None`` if not found.
    """
    return (
        args.token
        or os.environ.get("GITHUB_TOKEN")
        or os.environ.get("INPUT_GITHUB_TOKEN")
    )


def _resolve_repo(args: argparse.Namespace) -> Optional[str]:
    """Resolve the repository name from CLI args or environment variables.

    Args:
        args: Parsed command-line arguments.

    Returns:
        The repository string in ``owner/name`` format, or ``None``.
    """
    return args.repo or os.environ.get("GITHUB_REPOSITORY")


def _resolve_pr_number(args: argparse.Namespace) -> Optional[int]:
    """Resolve the PR number from CLI args or environment variables.

    Args:
        args: Parsed command-line arguments.

    Returns:
        The PR number as an integer, or ``None``.
    """
    if args.pr_number is not None:
        return args.pr_number
    env_val = os.environ.get("PR_NUMBER") or os.environ.get("INPUT_PR_NUMBER")
    if env_val:
        try:
            return int(env_val)
        except ValueError:
            return None
    return None


def _resolve_config_path(args: argparse.Namespace) -> str:
    """Resolve the configuration file path from CLI args or environment variables.

    Args:
        args: Parsed command-line arguments.

    Returns:
        Path string to the configuration file.
    """
    return (
        args.config_path
        or os.environ.get("PCG_CONFIG_PATH")
        or os.environ.get("INPUT_CONFIG_PATH")
        or ".pr_cost_gate.yml"
    )


def _load_and_merge_config(
    args: argparse.Namespace,
    config_path: str,
) -> GateConfig:
    """Load configuration and apply CLI argument and environment variable overrides.

    Order of precedence (highest wins):
    1. CLI arguments
    2. Environment variables (PCG_*)
    3. Configuration file (.pr_cost_gate.yml)
    4. Built-in defaults

    Args:
        args: Parsed command-line arguments.
        config_path: Path to the configuration file.

    Returns:
        A merged :class:`GateConfig` instance.

    Raises:
        ConfigError: If the config file contains invalid values.
        ConfigFileNotFoundError: If an explicit config path does not exist.
    """
    # Step 1: Load from file (or defaults)
    config = load_config(config_path)

    # Step 2: Apply environment variable overrides
    config = load_config_from_env(config)

    # Step 3: Apply CLI argument overrides
    from pr_cost_gate.config import (
        CommentConfig,
        GateConfig,
        SecurityConfig,
        ThresholdConfig,
    )

    # Model override
    if args.model is not None:
        config = GateConfig(
            model=args.model,
            thresholds=config.thresholds,
            security=config.security,
            comment=config.comment,
            exclusions=config.exclusions,
            tokens=config.tokens,
        )

    # Warn threshold override
    if args.warn_threshold_usd is not None:
        config = GateConfig(
            model=config.model,
            thresholds=ThresholdConfig(
                warn_usd=args.warn_threshold_usd,
                block_usd=config.thresholds.block_usd,
            ),
            security=config.security,
            comment=config.comment,
            exclusions=config.exclusions,
            tokens=config.tokens,
        )

    # Block threshold override
    if args.block_threshold_usd is not None:
        config = GateConfig(
            model=config.model,
            thresholds=ThresholdConfig(
                warn_usd=config.thresholds.warn_usd,
                block_usd=args.block_threshold_usd,
            ),
            security=config.security,
            comment=config.comment,
            exclusions=config.exclusions,
            tokens=config.tokens,
        )

    # No-comment override
    if args.no_comment:
        config = GateConfig(
            model=config.model,
            thresholds=config.thresholds,
            security=config.security,
            comment=CommentConfig(
                post=False,
                collapsible=config.comment.collapsible,
                post_when=config.comment.post_when,
            ),
            exclusions=config.exclusions,
            tokens=config.tokens,
        )

    # No-security override
    if args.no_security:
        config = GateConfig(
            model=config.model,
            thresholds=config.thresholds,
            security=SecurityConfig(
                enabled=False,
                patterns=config.security.patterns,
            ),
            comment=config.comment,
            exclusions=config.exclusions,
            tokens=config.tokens,
        )

    return config


# ---------------------------------------------------------------------------
# Verbose output helpers
# ---------------------------------------------------------------------------


def _print_analysis_summary(
    analysis: PRAnalysisResult,
    security: SecurityScanResult,
    risk_level: str,
    verbose: bool = False,
) -> None:
    """Print a human-readable summary to stdout.

    Args:
        analysis: PR analysis result.
        security: Security scan result.
        risk_level: Computed risk level string.
        verbose: When ``True``, print the per-file breakdown table.
    """
    _print_info(f"PR #{analysis.pr_number} in {analysis.repo} — {analysis.pr_title!r}")
    _print_info(f"Model: {analysis.model}")
    _print_info(
        f"Total tokens: {analysis.total_tokens:,} "
        f"(input: {analysis.input_tokens:,}, output: {analysis.output_tokens:,})"
    )
    _print_info(f"Estimated cost: ${analysis.estimated_cost_usd:.4f} USD")
    if analysis.any_capped:
        _print_warn("One or more files had their token count capped at max_per_file.")
    _print_info(
        f"Files analysed: {len(analysis.files)}, skipped: {len(analysis.skipped_files)}"
    )

    if verbose and analysis.files:
        _print_info("Per-file breakdown (sorted by tokens, descending):")
        sorted_files = sorted(analysis.files, key=lambda f: f.token_count, reverse=True)
        for fa in sorted_files:
            capped = " [CAPPED]" if fa.was_capped else ""
            _print_info(
                f"  {fa.filename}: {fa.token_count:,} tokens, "
                f"${fa.estimated_cost_usd:.4f} USD{capped}"
            )

    if security.total_count > 0:
        highest = security.highest_risk_level
        _print_warn(
            f"Security findings: {security.total_count} "
            f"(highest: {highest.value if highest else 'N/A'})"
        )
        if verbose:
            for finding in security.findings:
                _print_warn(
                    f"  [{finding.risk_level.value}] {finding.rule_id}: "
                    f"{finding.filename}:{finding.line_number} — {finding.description}"
                )
    else:
        _print_info("Security findings: none")

    emoji_map = {"OK": "✅", "WARN": "⚠️", "BLOCK": "🚫"}
    emoji = emoji_map.get(risk_level, "ℹ️")
    _print_info(f"Risk level: {emoji} {risk_level}")


# ---------------------------------------------------------------------------
# Core orchestration
# ---------------------------------------------------------------------------


def run(
    token: str,
    repo: str,
    pr_number: int,
    config: GateConfig,
    verbose: bool = False,
) -> tuple[str, PRAnalysisResult, SecurityScanResult, Optional[PostedComment]]:
    """Orchestrate the full analysis, security scan, and comment posting.

    This is the core business logic function, separated from argument parsing
    to make it testable independently.

    Args:
        token: GitHub API token.
        repo: Repository in ``owner/name`` format.
        pr_number: Pull request number.
        config: Fully-merged :class:`GateConfig`.
        verbose: Whether to print verbose output.

    Returns:
        A tuple ``(risk_level, analysis, security, posted_comment)``.

    Raises:
        PRNotFoundError: If the PR cannot be found.
        AnalyzerError: On GitHub API errors during analysis.
        CommentError: If comment posting fails.
    """
    # Step 1: Analyze the PR diff
    _print_info(f"Analysing PR #{pr_number} in {repo!r}...")
    analysis = analyze_pr(
        token=token,
        repo=repo,
        pr_number=pr_number,
        config=config,
    )
    _print_info(f"Analysis complete: {analysis.total_tokens:,} tokens across {len(analysis.files)} files.")

    # Step 2: Run security scan
    security: SecurityScanResult
    if config.security.enabled:
        _print_info("Running security scan...")
        security = scan_files(analysis.files, config=config)
        _print_info(f"Security scan complete: {security.total_count} finding(s).")
    else:
        _print_info("Security scan disabled — skipping.")
        security = SecurityScanResult()

    # Step 3: Determine risk level
    risk_level = determine_risk_level(analysis, security, config)

    # Step 4: Print summary
    _print_analysis_summary(analysis, security, risk_level, verbose=verbose)

    # Step 5: Build and post comment
    posted_comment: Optional[PostedComment] = None
    if config.comment.post:
        _print_info("Building and posting PR comment...")
        try:
            risk_level, posted_comment = build_and_post_comment(
                github_token=token,
                repo=repo,
                pr_number=pr_number,
                analysis=analysis,
                security=security,
                config=config,
            )
            if posted_comment is not None:
                action = "updated" if posted_comment.was_updated else "posted"
                _print_info(f"Comment {action}: {posted_comment.comment_url}")
            else:
                _print_info(
                    f"Comment not posted (post_when={config.comment.post_when!r}, "
                    f"risk_level={risk_level!r})."
                )
        except CommentError as exc:
            # Comment posting failure is non-fatal — log a warning but continue
            _print_warn(f"Failed to post comment: {exc}")
    else:
        _print_info("Comment posting disabled — skipping.")
        # Still compute the proper risk level without re-calling build_and_post_comment
        risk_level = determine_risk_level(analysis, security, config)

    return risk_level, analysis, security, posted_comment


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------


def main(argv: Optional[list[str]] = None) -> int:
    """CLI entry point for pr-cost-gate.

    Parses arguments, loads configuration, runs the analysis pipeline,
    and returns the appropriate exit code.

    Args:
        argv: Command-line argument list.  When ``None``, ``sys.argv[1:]``
            is used (standard behaviour for a CLI entry point).

    Returns:
        Integer exit code::

            0 — OK or WARN
            1 — BLOCK or unrecoverable runtime error
            2 — Configuration or argument error
    """
    parser = _build_parser()
    args = parser.parse_args(argv)

    # --- Resolve required inputs ---
    token = _resolve_token(args)
    if not token:
        _print_error(
            "GitHub token is required. Provide --token TOKEN or set the "
            "GITHUB_TOKEN environment variable."
        )
        return EXIT_CONFIG_ERROR

    repo = _resolve_repo(args)
    if not repo:
        _print_error(
            "Repository is required. Provide --repo OWNER/NAME or set the "
            "GITHUB_REPOSITORY environment variable."
        )
        return EXIT_CONFIG_ERROR

    pr_number = _resolve_pr_number(args)
    if pr_number is None:
        _print_error(
            "Pull request number is required. Provide --pr NUMBER or set the "
            "PR_NUMBER environment variable."
        )
        return EXIT_CONFIG_ERROR

    if pr_number <= 0:
        _print_error(f"Pull request number must be a positive integer, got {pr_number!r}.")
        return EXIT_CONFIG_ERROR

    # Validate repo format
    if "/" not in repo or repo.count("/") != 1:
        _print_error(
            f"Repository must be in 'owner/name' format, got {repo!r}."
        )
        return EXIT_CONFIG_ERROR

    # --- Load and merge configuration ---
    config_path = _resolve_config_path(args)
    try:
        config = _load_and_merge_config(args, config_path)
    except ConfigFileNotFoundError as exc:
        _print_error(f"Configuration file not found: {exc}")
        return EXIT_CONFIG_ERROR
    except ConfigError as exc:
        _print_error(f"Configuration error: {exc}")
        return EXIT_CONFIG_ERROR

    _print_info(
        f"Starting analysis — repo={repo!r}, PR=#{pr_number}, "
        f"model={config.model!r}, config={config_path!r}"
    )
    _print_info(
        f"Thresholds — warn=${config.thresholds.warn_usd:.2f}, "
        f"block=${config.thresholds.block_usd:.2f}"
    )

    # --- Run the analysis pipeline ---
    try:
        risk_level, analysis, security, posted_comment = run(
            token=token,
            repo=repo,
            pr_number=pr_number,
            config=config,
            verbose=args.verbose,
        )
    except PRNotFoundError as exc:
        _print_error(f"Pull request not found: {exc}")
        return EXIT_BLOCK
    except AnalyzerError as exc:
        _print_error(f"Analysis failed: {exc}")
        if args.verbose:
            traceback.print_exc(file=sys.stderr)
        return EXIT_BLOCK
    except KeyboardInterrupt:
        _print_error("Interrupted by user.")
        return EXIT_BLOCK
    except Exception as exc:
        _print_error(f"Unexpected error: {exc}")
        if args.verbose:
            traceback.print_exc(file=sys.stderr)
        return EXIT_BLOCK

    # --- Set GitHub Actions outputs ---
    _set_github_action_outputs(analysis, security, risk_level, posted_comment)

    # --- Determine exit code ---
    if risk_level == "BLOCK":
        _print_warn(
            f"Risk level is BLOCK — estimated cost ${analysis.estimated_cost_usd:.4f} USD "
            f"or security findings require attention. Exiting with status 1."
        )
        return EXIT_BLOCK

    _print_info(f"Done. Risk level: {risk_level}")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main())
