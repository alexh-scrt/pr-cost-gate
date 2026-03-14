"""Configuration loader and data models for pr_cost_gate.

Loads and validates the .pr_cost_gate.yml configuration file using PyYAML
and Python dataclasses. Provides sensible defaults for all settings and
raises descriptive errors for invalid configuration values.

Typical usage::

    from pr_cost_gate.config import load_config, GateConfig

    config = load_config(".pr_cost_gate.yml")
    print(config.model)              # 'gpt-4o'
    print(config.thresholds.warn_usd)  # 1.0
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

#: All supported AI model identifiers.
SUPPORTED_MODELS: frozenset[str] = frozenset(
    {
        "gpt-4o",
        "gpt-4-turbo",
        "claude-3-5-sonnet",
        "claude-3-opus",
        "claude-3-haiku",
    }
)

#: Default model when none is specified.
DEFAULT_MODEL: str = "gpt-4o"

#: Default path for the configuration file.
DEFAULT_CONFIG_PATH: str = ".pr_cost_gate.yml"

#: Valid values for ``comment.post_when``.
VALID_POST_WHEN: frozenset[str] = frozenset({"always", "warn", "block"})


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class ConfigError(ValueError):
    """Raised when the configuration file contains invalid values."""


class ConfigFileNotFoundError(FileNotFoundError):
    """Raised when the specified configuration file does not exist."""


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


@dataclass
class ThresholdConfig:
    """Cost threshold settings that govern WARN and BLOCK behaviour.

    Attributes:
        warn_usd: Estimated cost in USD that triggers a WARN annotation.
            Set to ``0.0`` to disable warnings.
        block_usd: Estimated cost in USD that triggers a non-zero exit (BLOCK).
            Set to ``0.0`` to disable blocking.
    """

    warn_usd: float = 1.00
    block_usd: float = 5.00

    def __post_init__(self) -> None:  # noqa: D105
        self._validate()

    def _validate(self) -> None:
        """Validate that threshold values are non-negative numbers."""
        if not isinstance(self.warn_usd, (int, float)):
            raise ConfigError(
                f"thresholds.warn_usd must be a number, got {type(self.warn_usd).__name__!r}"
            )
        if not isinstance(self.block_usd, (int, float)):
            raise ConfigError(
                f"thresholds.block_usd must be a number, "
                f"got {type(self.block_usd).__name__!r}"
            )
        if self.warn_usd < 0:
            raise ConfigError("thresholds.warn_usd must be >= 0")
        if self.block_usd < 0:
            raise ConfigError("thresholds.block_usd must be >= 0")


@dataclass
class SecurityPatternsConfig:
    """Toggle individual security pattern categories.

    Attributes:
        secrets: Scan for hardcoded API keys, tokens, and passwords.
        auth_changes: Flag authentication / authorization file changes.
        sql_injection: Detect raw SQL string construction patterns.
        dangerous_functions: Warn on eval(), exec(), etc.
        dependency_changes: Flag dependency manifest modifications.
    """

    secrets: bool = True
    auth_changes: bool = True
    sql_injection: bool = True
    dangerous_functions: bool = True
    dependency_changes: bool = True


@dataclass
class SecurityConfig:
    """Top-level security scanning configuration.

    Attributes:
        enabled: Master switch — set to ``False`` to skip all security scans.
        patterns: Fine-grained toggles for individual pattern categories.
    """

    enabled: bool = True
    patterns: SecurityPatternsConfig = field(default_factory=SecurityPatternsConfig)


@dataclass
class CommentConfig:
    """Settings that control PR comment rendering and posting.

    Attributes:
        post: Whether to post the summary comment to the pull request.
        collapsible: Wrap the per-file table in a ``<details>`` block.
        post_when: Minimum risk level required to post.
            One of ``'always'``, ``'warn'``, or ``'block'``.
    """

    post: bool = True
    collapsible: bool = True
    post_when: str = "always"

    def __post_init__(self) -> None:  # noqa: D105
        self._validate()

    def _validate(self) -> None:
        """Validate the ``post_when`` field."""
        if self.post_when not in VALID_POST_WHEN:
            raise ConfigError(
                f"comment.post_when must be one of {sorted(VALID_POST_WHEN)}, "
                f"got {self.post_when!r}"
            )


@dataclass
class ExclusionsConfig:
    """File path exclusion patterns.

    Attributes:
        paths: A list of glob patterns for files to skip during analysis.
            Patterns are matched against the file path reported by the GitHub API.
    """

    paths: list[str] = field(
        default_factory=lambda: [
            "**/*.lock",
            "**/vendor/**",
            "**/__pycache__/**",
            "**/*.min.js",
            "**/*.min.css",
            "**/node_modules/**",
            "**/*.pb.go",
            "**/*.pb.py",
        ]
    )


@dataclass
class TokenConfig:
    """Token counting behaviour settings.

    Attributes:
        max_per_file: Hard cap on tokens counted per file.
            Prevents runaway estimates for generated or minified files.
        diff_only: When ``True``, count only added/removed diff lines;
            when ``False``, include context lines as well.
    """

    max_per_file: int = 100_000
    diff_only: bool = True

    def __post_init__(self) -> None:  # noqa: D105
        self._validate()

    def _validate(self) -> None:
        """Validate token config fields."""
        if not isinstance(self.max_per_file, int) or self.max_per_file < 1:
            raise ConfigError("tokens.max_per_file must be a positive integer")


@dataclass
class GateConfig:
    """Root configuration object for pr_cost_gate.

    Holds all settings loaded from ``.pr_cost_gate.yml`` (or defaults when
    the file is absent or a field is omitted).

    Attributes:
        model: AI model identifier used for cost estimation.
        thresholds: Cost thresholds for WARN and BLOCK actions.
        security: Security scanning settings.
        comment: PR comment rendering and posting settings.
        exclusions: File path exclusion glob patterns.
        tokens: Token counting behaviour settings.
    """

    model: str = DEFAULT_MODEL
    thresholds: ThresholdConfig = field(default_factory=ThresholdConfig)
    security: SecurityConfig = field(default_factory=SecurityConfig)
    comment: CommentConfig = field(default_factory=CommentConfig)
    exclusions: ExclusionsConfig = field(default_factory=ExclusionsConfig)
    tokens: TokenConfig = field(default_factory=TokenConfig)

    def __post_init__(self) -> None:  # noqa: D105
        self._validate()

    def _validate(self) -> None:
        """Validate top-level fields."""
        if self.model not in SUPPORTED_MODELS:
            raise ConfigError(
                f"model must be one of {sorted(SUPPORTED_MODELS)}, got {self.model!r}"
            )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------


def _parse_thresholds(raw: Any) -> ThresholdConfig:
    """Parse and return a :class:`ThresholdConfig` from raw YAML data.

    Args:
        raw: The value of the ``thresholds`` key in the YAML file.
            Expected to be a mapping (dict) or ``None``.

    Returns:
        A validated :class:`ThresholdConfig` instance.

    Raises:
        ConfigError: If *raw* is not a mapping or contains invalid values.
    """
    if raw is None:
        return ThresholdConfig()
    if not isinstance(raw, dict):
        raise ConfigError(f"thresholds must be a mapping, got {type(raw).__name__!r}")
    return ThresholdConfig(
        warn_usd=float(raw.get("warn_usd", ThresholdConfig.warn_usd)),
        block_usd=float(raw.get("block_usd", ThresholdConfig.block_usd)),
    )


def _parse_security(raw: Any) -> SecurityConfig:
    """Parse and return a :class:`SecurityConfig` from raw YAML data.

    Args:
        raw: The value of the ``security`` key in the YAML file.

    Returns:
        A validated :class:`SecurityConfig` instance.

    Raises:
        ConfigError: If *raw* is not a mapping.
    """
    if raw is None:
        return SecurityConfig()
    if not isinstance(raw, dict):
        raise ConfigError(f"security must be a mapping, got {type(raw).__name__!r}")

    patterns_raw = raw.get("patterns", {})
    if not isinstance(patterns_raw, dict):
        raise ConfigError(
            f"security.patterns must be a mapping, got {type(patterns_raw).__name__!r}"
        )

    patterns = SecurityPatternsConfig(
        secrets=bool(patterns_raw.get("secrets", SecurityPatternsConfig.secrets)),
        auth_changes=bool(
            patterns_raw.get("auth_changes", SecurityPatternsConfig.auth_changes)
        ),
        sql_injection=bool(
            patterns_raw.get("sql_injection", SecurityPatternsConfig.sql_injection)
        ),
        dangerous_functions=bool(
            patterns_raw.get(
                "dangerous_functions", SecurityPatternsConfig.dangerous_functions
            )
        ),
        dependency_changes=bool(
            patterns_raw.get(
                "dependency_changes", SecurityPatternsConfig.dependency_changes
            )
        ),
    )
    return SecurityConfig(
        enabled=bool(raw.get("enabled", SecurityConfig.enabled)),
        patterns=patterns,
    )


def _parse_comment(raw: Any) -> CommentConfig:
    """Parse and return a :class:`CommentConfig` from raw YAML data.

    Args:
        raw: The value of the ``comment`` key in the YAML file.

    Returns:
        A validated :class:`CommentConfig` instance.

    Raises:
        ConfigError: If *raw* is not a mapping or ``post_when`` is invalid.
    """
    if raw is None:
        return CommentConfig()
    if not isinstance(raw, dict):
        raise ConfigError(f"comment must be a mapping, got {type(raw).__name__!r}")
    return CommentConfig(
        post=bool(raw.get("post", CommentConfig.post)),
        collapsible=bool(raw.get("collapsible", CommentConfig.collapsible)),
        post_when=str(raw.get("post_when", CommentConfig.post_when)),
    )


def _parse_exclusions(raw: Any) -> ExclusionsConfig:
    """Parse and return an :class:`ExclusionsConfig` from raw YAML data.

    Args:
        raw: The value of the ``exclusions`` key in the YAML file.

    Returns:
        An :class:`ExclusionsConfig` instance.

    Raises:
        ConfigError: If *raw* is not a mapping or ``paths`` is not a list.
    """
    if raw is None:
        return ExclusionsConfig()
    if not isinstance(raw, dict):
        raise ConfigError(f"exclusions must be a mapping, got {type(raw).__name__!r}")

    paths_raw = raw.get("paths", None)
    if paths_raw is None:
        return ExclusionsConfig()
    if not isinstance(paths_raw, list):
        raise ConfigError(
            f"exclusions.paths must be a list, got {type(paths_raw).__name__!r}"
        )
    return ExclusionsConfig(paths=[str(p) for p in paths_raw])


def _parse_tokens(raw: Any) -> TokenConfig:
    """Parse and return a :class:`TokenConfig` from raw YAML data.

    Args:
        raw: The value of the ``tokens`` key in the YAML file.

    Returns:
        A validated :class:`TokenConfig` instance.

    Raises:
        ConfigError: If *raw* is not a mapping or contains invalid values.
    """
    if raw is None:
        return TokenConfig()
    if not isinstance(raw, dict):
        raise ConfigError(f"tokens must be a mapping, got {type(raw).__name__!r}")
    raw_max = raw.get("max_per_file", TokenConfig.max_per_file)
    try:
        max_per_file = int(raw_max)
    except (TypeError, ValueError) as exc:
        raise ConfigError(
            f"tokens.max_per_file must be an integer, got {raw_max!r}"
        ) from exc
    return TokenConfig(
        max_per_file=max_per_file,
        diff_only=bool(raw.get("diff_only", TokenConfig.diff_only)),
    )


def _from_dict(data: dict[str, Any]) -> GateConfig:
    """Build a :class:`GateConfig` from a parsed YAML dictionary.

    Args:
        data: Top-level dict produced by ``yaml.safe_load``.

    Returns:
        A fully validated :class:`GateConfig`.

    Raises:
        ConfigError: If any field contains an invalid value.
    """
    return GateConfig(
        model=str(data.get("model", DEFAULT_MODEL)),
        thresholds=_parse_thresholds(data.get("thresholds")),
        security=_parse_security(data.get("security")),
        comment=_parse_comment(data.get("comment")),
        exclusions=_parse_exclusions(data.get("exclusions")),
        tokens=_parse_tokens(data.get("tokens")),
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def load_config(path: str | os.PathLike[str] = DEFAULT_CONFIG_PATH) -> GateConfig:
    """Load configuration from a YAML file, falling back to defaults.

    If *path* does not exist the function returns a :class:`GateConfig` with
    all default values — this is the intended behaviour for projects that have
    not yet created a ``.pr_cost_gate.yml`` file.

    Args:
        path: Path to the YAML configuration file.  Defaults to
            ``'.pr_cost_gate.yml'`` in the current working directory.

    Returns:
        A validated :class:`GateConfig` populated from the file (or defaults).

    Raises:
        ConfigError: If the file exists but contains invalid YAML or invalid
            configuration values.
        ConfigFileNotFoundError: If *path* is explicitly provided (i.e. not the
            default) but does not exist on disk.
    """
    config_path = Path(path)
    is_default_path = str(path) == DEFAULT_CONFIG_PATH

    if not config_path.exists():
        if is_default_path:
            # Silently fall back to defaults when using the default path.
            return GateConfig()
        raise ConfigFileNotFoundError(
            f"Configuration file not found: {config_path}"
        )

    try:
        raw_text = config_path.read_text(encoding="utf-8")
    except OSError as exc:
        raise ConfigError(f"Cannot read configuration file {config_path}: {exc}") from exc

    try:
        data = yaml.safe_load(raw_text)
    except yaml.YAMLError as exc:
        raise ConfigError(f"Invalid YAML in {config_path}: {exc}") from exc

    if data is None:
        # Empty file — use all defaults.
        return GateConfig()

    if not isinstance(data, dict):
        raise ConfigError(
            f"Configuration file must be a YAML mapping at the top level, "
            f"got {type(data).__name__!r}"
        )

    try:
        return _from_dict(data)
    except ConfigError:
        raise
    except Exception as exc:  # pragma: no cover — safety net
        raise ConfigError(f"Unexpected error parsing {config_path}: {exc}") from exc


def load_config_from_env(base_config: GateConfig | None = None) -> GateConfig:
    """Override configuration fields from environment variables.

    Environment variables take precedence over values in the config file.
    This is used by the GitHub Action to apply action-input overrides.

    Recognised environment variables:

    * ``PCG_MODEL`` — overrides ``model``
    * ``PCG_WARN_THRESHOLD_USD`` — overrides ``thresholds.warn_usd``
    * ``PCG_BLOCK_THRESHOLD_USD`` — overrides ``thresholds.block_usd``
    * ``PCG_POST_COMMENT`` — overrides ``comment.post`` (``'true'``/``'false'``)
    * ``PCG_SECURITY_SCAN`` — overrides ``security.enabled`` (``'true'``/``'false'``)

    Args:
        base_config: Starting configuration.  When ``None``, begins with
            all defaults.

    Returns:
        A new :class:`GateConfig` with environment variable overrides applied.

    Raises:
        ConfigError: If an environment variable contains an invalid value.
    """
    cfg = base_config if base_config is not None else GateConfig()

    # --- model ---
    model_env = os.environ.get("PCG_MODEL")
    if model_env:
        if model_env not in SUPPORTED_MODELS:
            raise ConfigError(
                f"PCG_MODEL must be one of {sorted(SUPPORTED_MODELS)}, "
                f"got {model_env!r}"
            )
        cfg = GateConfig(
            model=model_env,
            thresholds=cfg.thresholds,
            security=cfg.security,
            comment=cfg.comment,
            exclusions=cfg.exclusions,
            tokens=cfg.tokens,
        )

    # --- warn threshold ---
    warn_env = os.environ.get("PCG_WARN_THRESHOLD_USD")
    if warn_env:
        try:
            warn_val = float(warn_env)
        except ValueError as exc:
            raise ConfigError(
                f"PCG_WARN_THRESHOLD_USD must be a number, got {warn_env!r}"
            ) from exc
        cfg = GateConfig(
            model=cfg.model,
            thresholds=ThresholdConfig(
                warn_usd=warn_val, block_usd=cfg.thresholds.block_usd
            ),
            security=cfg.security,
            comment=cfg.comment,
            exclusions=cfg.exclusions,
            tokens=cfg.tokens,
        )

    # --- block threshold ---
    block_env = os.environ.get("PCG_BLOCK_THRESHOLD_USD")
    if block_env:
        try:
            block_val = float(block_env)
        except ValueError as exc:
            raise ConfigError(
                f"PCG_BLOCK_THRESHOLD_USD must be a number, got {block_env!r}"
            ) from exc
        cfg = GateConfig(
            model=cfg.model,
            thresholds=ThresholdConfig(
                warn_usd=cfg.thresholds.warn_usd, block_usd=block_val
            ),
            security=cfg.security,
            comment=cfg.comment,
            exclusions=cfg.exclusions,
            tokens=cfg.tokens,
        )

    # --- post comment ---
    post_env = os.environ.get("PCG_POST_COMMENT")
    if post_env:
        post_val = post_env.strip().lower() not in {"false", "0", "no"}
        cfg = GateConfig(
            model=cfg.model,
            thresholds=cfg.thresholds,
            security=cfg.security,
            comment=CommentConfig(
                post=post_val,
                collapsible=cfg.comment.collapsible,
                post_when=cfg.comment.post_when,
            ),
            exclusions=cfg.exclusions,
            tokens=cfg.tokens,
        )

    # --- security scan ---
    sec_env = os.environ.get("PCG_SECURITY_SCAN")
    if sec_env:
        sec_val = sec_env.strip().lower() not in {"false", "0", "no"}
        cfg = GateConfig(
            model=cfg.model,
            thresholds=cfg.thresholds,
            security=SecurityConfig(
                enabled=sec_val,
                patterns=cfg.security.patterns,
            ),
            comment=cfg.comment,
            exclusions=cfg.exclusions,
            tokens=cfg.tokens,
        )

    return cfg
