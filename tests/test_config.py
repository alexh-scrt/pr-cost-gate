"""Unit tests for pr_cost_gate.config.

Covers:
- Default value correctness for all dataclass fields
- Loading a valid .pr_cost_gate.yml file
- Loading an empty / missing config file
- Invalid model names
- Invalid threshold values
- Invalid comment.post_when
- Invalid security and token settings
- Environment variable overrides via load_config_from_env
- ConfigError and ConfigFileNotFoundError propagation
"""

from __future__ import annotations

import os
import textwrap
from pathlib import Path

import pytest

from pr_cost_gate.config import (
    CommentConfig,
    ConfigError,
    ConfigFileNotFoundError,
    ExclusionsConfig,
    GateConfig,
    SecurityConfig,
    SecurityPatternsConfig,
    ThresholdConfig,
    TokenConfig,
    load_config,
    load_config_from_env,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def write_yaml(tmp_path: Path, content: str, filename: str = ".pr_cost_gate.yml") -> Path:
    """Write *content* to a YAML file inside *tmp_path* and return its path."""
    p = tmp_path / filename
    p.write_text(textwrap.dedent(content), encoding="utf-8")
    return p


# ---------------------------------------------------------------------------
# Default value tests
# ---------------------------------------------------------------------------


class TestDefaults:
    """Verify that all dataclass defaults match the documented values."""

    def test_gate_config_defaults(self) -> None:
        cfg = GateConfig()
        assert cfg.model == "gpt-4o"

    def test_threshold_config_defaults(self) -> None:
        t = ThresholdConfig()
        assert t.warn_usd == pytest.approx(1.00)
        assert t.block_usd == pytest.approx(5.00)

    def test_security_config_defaults(self) -> None:
        s = SecurityConfig()
        assert s.enabled is True

    def test_security_patterns_defaults(self) -> None:
        p = SecurityPatternsConfig()
        assert p.secrets is True
        assert p.auth_changes is True
        assert p.sql_injection is True
        assert p.dangerous_functions is True
        assert p.dependency_changes is True

    def test_comment_config_defaults(self) -> None:
        c = CommentConfig()
        assert c.post is True
        assert c.collapsible is True
        assert c.post_when == "always"

    def test_exclusions_config_defaults(self) -> None:
        e = ExclusionsConfig()
        assert "**/*.lock" in e.paths
        assert "**/vendor/**" in e.paths

    def test_token_config_defaults(self) -> None:
        t = TokenConfig()
        assert t.max_per_file == 100_000
        assert t.diff_only is True

    def test_gate_config_nested_defaults(self) -> None:
        cfg = GateConfig()
        assert cfg.thresholds.warn_usd == pytest.approx(1.00)
        assert cfg.thresholds.block_usd == pytest.approx(5.00)
        assert cfg.security.enabled is True
        assert cfg.comment.post_when == "always"
        assert cfg.tokens.max_per_file == 100_000


# ---------------------------------------------------------------------------
# load_config – missing / empty file
# ---------------------------------------------------------------------------


class TestLoadConfigMissingFile:
    """load_config should return defaults when the default path doesn't exist."""

    def test_missing_default_path_returns_defaults(self, tmp_path: Path) -> None:
        nonexistent = tmp_path / ".pr_cost_gate.yml"
        cfg = load_config(nonexistent)
        assert isinstance(cfg, GateConfig)
        assert cfg.model == "gpt-4o"

    def test_missing_custom_path_raises(self, tmp_path: Path) -> None:
        custom = tmp_path / "custom_config.yml"
        with pytest.raises(ConfigFileNotFoundError):
            load_config(custom)

    def test_empty_file_returns_defaults(self, tmp_path: Path) -> None:
        p = write_yaml(tmp_path, "")
        cfg = load_config(p)
        assert cfg.model == "gpt-4o"
        assert cfg.thresholds.warn_usd == pytest.approx(1.00)


# ---------------------------------------------------------------------------
# load_config – valid full config
# ---------------------------------------------------------------------------


class TestLoadConfigValid:
    """load_config should correctly parse all fields from a valid YAML file."""

    FULL_YAML = """
        model: claude-3-5-sonnet

        thresholds:
          warn_usd: 2.50
          block_usd: 10.00

        security:
          enabled: false
          patterns:
            secrets: true
            auth_changes: false
            sql_injection: true
            dangerous_functions: false
            dependency_changes: true

        comment:
          post: false
          collapsible: false
          post_when: block

        exclusions:
          paths:
            - "**/*.txt"
            - "docs/**"

        tokens:
          max_per_file: 50000
          diff_only: false
    """

    def test_model_parsed(self, tmp_path: Path) -> None:
        cfg = load_config(write_yaml(tmp_path, self.FULL_YAML))
        assert cfg.model == "claude-3-5-sonnet"

    def test_thresholds_parsed(self, tmp_path: Path) -> None:
        cfg = load_config(write_yaml(tmp_path, self.FULL_YAML))
        assert cfg.thresholds.warn_usd == pytest.approx(2.50)
        assert cfg.thresholds.block_usd == pytest.approx(10.00)

    def test_security_enabled_false(self, tmp_path: Path) -> None:
        cfg = load_config(write_yaml(tmp_path, self.FULL_YAML))
        assert cfg.security.enabled is False

    def test_security_patterns_mixed(self, tmp_path: Path) -> None:
        cfg = load_config(write_yaml(tmp_path, self.FULL_YAML))
        assert cfg.security.patterns.secrets is True
        assert cfg.security.patterns.auth_changes is False
        assert cfg.security.patterns.sql_injection is True
        assert cfg.security.patterns.dangerous_functions is False
        assert cfg.security.patterns.dependency_changes is True

    def test_comment_parsed(self, tmp_path: Path) -> None:
        cfg = load_config(write_yaml(tmp_path, self.FULL_YAML))
        assert cfg.comment.post is False
        assert cfg.comment.collapsible is False
        assert cfg.comment.post_when == "block"

    def test_exclusions_parsed(self, tmp_path: Path) -> None:
        cfg = load_config(write_yaml(tmp_path, self.FULL_YAML))
        assert cfg.exclusions.paths == ["**/*.txt", "docs/**"]

    def test_tokens_parsed(self, tmp_path: Path) -> None:
        cfg = load_config(write_yaml(tmp_path, self.FULL_YAML))
        assert cfg.tokens.max_per_file == 50_000
        assert cfg.tokens.diff_only is False

    def test_partial_config_uses_defaults_for_missing(self, tmp_path: Path) -> None:
        """A config that only sets 'model' should use defaults for everything else."""
        p = write_yaml(tmp_path, "model: gpt-4-turbo\n")
        cfg = load_config(p)
        assert cfg.model == "gpt-4-turbo"
        assert cfg.thresholds.warn_usd == pytest.approx(1.00)
        assert cfg.security.enabled is True
        assert cfg.comment.post is True


# ---------------------------------------------------------------------------
# load_config – invalid values
# ---------------------------------------------------------------------------


class TestLoadConfigInvalid:
    """load_config should raise ConfigError for invalid field values."""

    def test_invalid_model(self, tmp_path: Path) -> None:
        p = write_yaml(tmp_path, "model: gpt-99\n")
        with pytest.raises(ConfigError, match="model"):
            load_config(p)

    def test_invalid_yaml_syntax(self, tmp_path: Path) -> None:
        p = tmp_path / ".pr_cost_gate.yml"
        p.write_text("model: [unclosed", encoding="utf-8")
        with pytest.raises(ConfigError, match="YAML"):
            load_config(p)

    def test_non_mapping_top_level(self, tmp_path: Path) -> None:
        p = write_yaml(tmp_path, "- item1\n- item2\n")
        with pytest.raises(ConfigError):
            load_config(p)

    def test_negative_warn_threshold(self, tmp_path: Path) -> None:
        p = write_yaml(tmp_path, "thresholds:\n  warn_usd: -1\n")
        with pytest.raises(ConfigError, match="warn_usd"):
            load_config(p)

    def test_negative_block_threshold(self, tmp_path: Path) -> None:
        p = write_yaml(tmp_path, "thresholds:\n  block_usd: -0.01\n")
        with pytest.raises(ConfigError, match="block_usd"):
            load_config(p)

    def test_invalid_post_when(self, tmp_path: Path) -> None:
        p = write_yaml(tmp_path, "comment:\n  post_when: never\n")
        with pytest.raises(ConfigError, match="post_when"):
            load_config(p)

    def test_non_mapping_thresholds(self, tmp_path: Path) -> None:
        p = write_yaml(tmp_path, "thresholds: 5\n")
        with pytest.raises(ConfigError, match="thresholds"):
            load_config(p)

    def test_non_mapping_security(self, tmp_path: Path) -> None:
        p = write_yaml(tmp_path, "security: yes\n")
        with pytest.raises(ConfigError, match="security"):
            load_config(p)

    def test_non_mapping_comment(self, tmp_path: Path) -> None:
        p = write_yaml(tmp_path, "comment: 42\n")
        with pytest.raises(ConfigError, match="comment"):
            load_config(p)

    def test_non_mapping_exclusions(self, tmp_path: Path) -> None:
        p = write_yaml(tmp_path, "exclusions: true\n")
        with pytest.raises(ConfigError, match="exclusions"):
            load_config(p)

    def test_non_list_exclusion_paths(self, tmp_path: Path) -> None:
        p = write_yaml(tmp_path, "exclusions:\n  paths: not-a-list\n")
        with pytest.raises(ConfigError, match="paths"):
            load_config(p)

    def test_non_mapping_tokens(self, tmp_path: Path) -> None:
        p = write_yaml(tmp_path, "tokens: 100\n")
        with pytest.raises(ConfigError, match="tokens"):
            load_config(p)

    def test_invalid_max_per_file(self, tmp_path: Path) -> None:
        p = write_yaml(tmp_path, "tokens:\n  max_per_file: 0\n")
        with pytest.raises(ConfigError, match="max_per_file"):
            load_config(p)

    def test_non_integer_max_per_file(self, tmp_path: Path) -> None:
        p = write_yaml(tmp_path, "tokens:\n  max_per_file: abc\n")
        with pytest.raises(ConfigError, match="max_per_file"):
            load_config(p)

    def test_non_mapping_security_patterns(self, tmp_path: Path) -> None:
        p = write_yaml(tmp_path, "security:\n  patterns: bad\n")
        with pytest.raises(ConfigError, match="patterns"):
            load_config(p)


# ---------------------------------------------------------------------------
# ThresholdConfig direct instantiation
# ---------------------------------------------------------------------------


class TestThresholdConfig:
    def test_zero_thresholds_allowed(self) -> None:
        t = ThresholdConfig(warn_usd=0.0, block_usd=0.0)
        assert t.warn_usd == 0.0
        assert t.block_usd == 0.0

    def test_invalid_warn_type(self) -> None:
        with pytest.raises(ConfigError):
            ThresholdConfig(warn_usd="high", block_usd=5.0)  # type: ignore[arg-type]

    def test_invalid_block_type(self) -> None:
        with pytest.raises(ConfigError):
            ThresholdConfig(warn_usd=1.0, block_usd="lots")  # type: ignore[arg-type]


# ---------------------------------------------------------------------------
# CommentConfig direct instantiation
# ---------------------------------------------------------------------------


class TestCommentConfig:
    def test_valid_post_when_values(self) -> None:
        for value in ("always", "warn", "block"):
            cfg = CommentConfig(post_when=value)
            assert cfg.post_when == value

    def test_invalid_post_when(self) -> None:
        with pytest.raises(ConfigError, match="post_when"):
            CommentConfig(post_when="sometimes")


# ---------------------------------------------------------------------------
# TokenConfig direct instantiation
# ---------------------------------------------------------------------------


class TestTokenConfig:
    def test_valid_max_per_file(self) -> None:
        t = TokenConfig(max_per_file=50_000)
        assert t.max_per_file == 50_000

    def test_zero_max_per_file_raises(self) -> None:
        with pytest.raises(ConfigError):
            TokenConfig(max_per_file=0)

    def test_negative_max_per_file_raises(self) -> None:
        with pytest.raises(ConfigError):
            TokenConfig(max_per_file=-1)


# ---------------------------------------------------------------------------
# load_config_from_env
# ---------------------------------------------------------------------------


class TestLoadConfigFromEnv:
    """load_config_from_env should override config fields from env vars."""

    def _clean_env(self, monkeypatch: pytest.MonkeyPatch) -> None:
        """Remove all PCG_* environment variables to prevent test pollution."""
        for key in [
            "PCG_MODEL",
            "PCG_WARN_THRESHOLD_USD",
            "PCG_BLOCK_THRESHOLD_USD",
            "PCG_POST_COMMENT",
            "PCG_SECURITY_SCAN",
        ]:
            monkeypatch.delenv(key, raising=False)

    def test_no_env_vars_returns_base(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        base = GateConfig()
        result = load_config_from_env(base)
        assert result.model == base.model

    def test_pcg_model_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        monkeypatch.setenv("PCG_MODEL", "claude-3-opus")
        result = load_config_from_env(GateConfig())
        assert result.model == "claude-3-opus"

    def test_pcg_model_invalid_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        monkeypatch.setenv("PCG_MODEL", "gpt-99")
        with pytest.raises(ConfigError, match="PCG_MODEL"):
            load_config_from_env()

    def test_pcg_warn_threshold_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        monkeypatch.setenv("PCG_WARN_THRESHOLD_USD", "3.00")
        result = load_config_from_env(GateConfig())
        assert result.thresholds.warn_usd == pytest.approx(3.00)

    def test_pcg_block_threshold_overrides(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        monkeypatch.setenv("PCG_BLOCK_THRESHOLD_USD", "20.00")
        result = load_config_from_env(GateConfig())
        assert result.thresholds.block_usd == pytest.approx(20.00)

    def test_pcg_warn_threshold_invalid_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        monkeypatch.setenv("PCG_WARN_THRESHOLD_USD", "not-a-number")
        with pytest.raises(ConfigError, match="PCG_WARN_THRESHOLD_USD"):
            load_config_from_env()

    def test_pcg_block_threshold_invalid_raises(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        monkeypatch.setenv("PCG_BLOCK_THRESHOLD_USD", "abc")
        with pytest.raises(ConfigError, match="PCG_BLOCK_THRESHOLD_USD"):
            load_config_from_env()

    def test_pcg_post_comment_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        for falsy in ("false", "False", "FALSE", "0", "no"):
            monkeypatch.setenv("PCG_POST_COMMENT", falsy)
            result = load_config_from_env(GateConfig())
            assert result.comment.post is False, f"Expected False for {falsy!r}"

    def test_pcg_post_comment_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        for truthy in ("true", "True", "1", "yes"):
            monkeypatch.setenv("PCG_POST_COMMENT", truthy)
            result = load_config_from_env(GateConfig())
            assert result.comment.post is True, f"Expected True for {truthy!r}"

    def test_pcg_security_scan_false(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        monkeypatch.setenv("PCG_SECURITY_SCAN", "false")
        result = load_config_from_env(GateConfig())
        assert result.security.enabled is False

    def test_pcg_security_scan_true(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        monkeypatch.setenv("PCG_SECURITY_SCAN", "true")
        result = load_config_from_env(GateConfig())
        assert result.security.enabled is True

    def test_no_base_config_uses_defaults(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        result = load_config_from_env()
        assert result.model == "gpt-4o"

    def test_multiple_env_vars_all_applied(self, monkeypatch: pytest.MonkeyPatch) -> None:
        self._clean_env(monkeypatch)
        monkeypatch.setenv("PCG_MODEL", "gpt-4-turbo")
        monkeypatch.setenv("PCG_WARN_THRESHOLD_USD", "0.50")
        monkeypatch.setenv("PCG_BLOCK_THRESHOLD_USD", "2.00")
        monkeypatch.setenv("PCG_POST_COMMENT", "false")
        monkeypatch.setenv("PCG_SECURITY_SCAN", "false")
        result = load_config_from_env(GateConfig())
        assert result.model == "gpt-4-turbo"
        assert result.thresholds.warn_usd == pytest.approx(0.50)
        assert result.thresholds.block_usd == pytest.approx(2.00)
        assert result.comment.post is False
        assert result.security.enabled is False

    def test_env_overrides_file_config(self, monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
        """Env vars should override values loaded from a file."""
        self._clean_env(monkeypatch)
        p = write_yaml(tmp_path, "model: claude-3-haiku\n")
        file_cfg = load_config(p)
        assert file_cfg.model == "claude-3-haiku"

        monkeypatch.setenv("PCG_MODEL", "gpt-4o")
        result = load_config_from_env(file_cfg)
        assert result.model == "gpt-4o"
        # Other values from file should be preserved
        assert result.thresholds.warn_usd == file_cfg.thresholds.warn_usd


# ---------------------------------------------------------------------------
# Edge-case round-trip tests
# ---------------------------------------------------------------------------


class TestEdgeCases:
    def test_zero_cost_thresholds_in_file(self, tmp_path: Path) -> None:
        p = write_yaml(tmp_path, "thresholds:\n  warn_usd: 0\n  block_usd: 0\n")
        cfg = load_config(p)
        assert cfg.thresholds.warn_usd == 0.0
        assert cfg.thresholds.block_usd == 0.0

    def test_all_security_patterns_disabled(self, tmp_path: Path) -> None:
        yaml_content = """
            security:
              enabled: true
              patterns:
                secrets: false
                auth_changes: false
                sql_injection: false
                dangerous_functions: false
                dependency_changes: false
        """
        cfg = load_config(write_yaml(tmp_path, yaml_content))
        assert cfg.security.enabled is True
        p = cfg.security.patterns
        assert p.secrets is False
        assert p.auth_changes is False
        assert p.sql_injection is False
        assert p.dangerous_functions is False
        assert p.dependency_changes is False

    def test_empty_exclusions_list(self, tmp_path: Path) -> None:
        p = write_yaml(tmp_path, "exclusions:\n  paths: []\n")
        cfg = load_config(p)
        assert cfg.exclusions.paths == []

    def test_large_max_per_file(self, tmp_path: Path) -> None:
        p = write_yaml(tmp_path, "tokens:\n  max_per_file: 1000000\n")
        cfg = load_config(p)
        assert cfg.tokens.max_per_file == 1_000_000

    def test_all_supported_models(self, tmp_path: Path) -> None:
        from pr_cost_gate.config import SUPPORTED_MODELS

        for model in sorted(SUPPORTED_MODELS):
            p = write_yaml(tmp_path, f"model: {model}\n", filename=f"cfg_{model}.yml")
            cfg = load_config(p)
            assert cfg.model == model

    def test_config_file_not_found_error_is_file_not_found(self) -> None:
        assert issubclass(ConfigFileNotFoundError, FileNotFoundError)

    def test_config_error_is_value_error(self) -> None:
        assert issubclass(ConfigError, ValueError)
