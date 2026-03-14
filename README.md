# pr_cost_gate

> **Prevent surprise $15–25 per-PR charges** from AI code review tools by analysing diffs for token counts, estimated costs, and security risks *before* triggering expensive models.

[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-ready-blue?logo=github)](#github-action-usage)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python)](#installation)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Quick Start](#quick-start)
  - [GitHub Action Usage](#github-action-usage)
  - [CLI Usage](#cli-usage)
- [Installation](#installation)
- [Configuration Reference](#configuration-reference)
  - [Model Selection](#model-selection)
  - [Cost Thresholds](#cost-thresholds)
  - [Security Scanning](#security-scanning)
  - [Comment Settings](#comment-settings)
  - [File Exclusions](#file-exclusions)
  - [Token Counting](#token-counting)
- [AI Model Pricing Table](#ai-model-pricing-table)
- [Security Risk Patterns](#security-risk-patterns)
- [Example PR Comment](#example-pr-comment)
- [Exit Codes](#exit-codes)
- [Environment Variables](#environment-variables)
- [Development](#development)
- [Contributing](#contributing)
- [License](#license)

---

## Overview

`pr_cost_gate` is a GitHub Action and CLI tool that sits in your CI pipeline **before** any AI code review step. For each pull request it:

1. **Fetches the PR diff** via the GitHub API
2. **Counts tokens** per changed file using [tiktoken](https://github.com/openai/tiktoken) (the same tokenizer used by OpenAI models)
3. **Estimates the AI review cost** against a configurable pricing table for GPT-4o, Claude 3.5 Sonnet, Claude 3 Opus, and others
4. **Scans diff hunks** for hardcoded secrets, auth changes, raw SQL, dangerous function calls, and dependency manifest changes
5. **Posts a structured Markdown comment** directly to the PR with a collapsible per-file breakdown
6. **Sets the workflow exit code** — optionally blocking downstream AI review steps when cost or risk thresholds are exceeded

---

## Features

| Feature | Details |
|---------|--------|
| 🎯 **Token-accurate cost estimation** | Uses tiktoken with model-specific encodings (o200k_base for GPT-4o, cl100k_base for others) |
| 🔒 **Security risk scanner** | 5 categories, 25+ rules covering secrets, auth, SQL injection, dangerous functions, and dependencies |
| ⚡ **Configurable thresholds** | WARN and BLOCK levels in USD — emit a badge or halt the workflow entirely |
| 💬 **Auto PR comments** | Collapsible Markdown tables posted/updated on every run via the GitHub API |
| 🛠️ **Zero-config defaults** | Sensible defaults work out of the box; `.pr_cost_gate.yml` for customisation |
| 🖥️ **Local CLI** | Run `pr-cost-gate` locally for pre-push checks |
| 🐳 **Docker-based Action** | Runs in a minimal Python 3.12 container |

---

## Quick Start

### GitHub Action Usage

Add to `.github/workflows/ai-review.yml`:

```yaml
name: AI Code Review

on:
  pull_request:
    types: [opened, synchronize, reopened]

jobs:
  cost-gate:
    name: PR Cost Gate
    runs-on: ubuntu-latest
    permissions:
      pull-requests: write   # required to post comments
      contents: read

    steps:
      - name: Check PR cost and security risks
        uses: your-org/pr_cost_gate@v1
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          model: gpt-4o
          warn_threshold_usd: "1.00"
          block_threshold_usd: "5.00"

  ai-review:
    name: AI Code Review
    needs: cost-gate   # ← only runs if cost-gate exits 0
    runs-on: ubuntu-latest
    steps:
      - name: Run expensive AI review
        run: |
          # your ai review tool here
          echo "Running AI review..."
```

#### Action Inputs

| Input | Required | Default | Description |
|-------|----------|---------|-------------|
| `github_token` | ✅ | `${{ github.token }}` | Token used to read PR diffs and post comments |
| `pr_number` | ❌ | `${{ github.event.pull_request.number }}` | PR number to analyse |
| `repo` | ❌ | `${{ github.repository }}` | Repository in `owner/name` format |
| `model` | ❌ | `gpt-4o` | AI model for cost estimation |
| `warn_threshold_usd` | ❌ | `1.00` | Cost threshold (USD) for WARN badge |
| `block_threshold_usd` | ❌ | `5.00` | Cost threshold (USD) to block workflow |
| `config_path` | ❌ | `.pr_cost_gate.yml` | Path to config file in the repository |
| `post_comment` | ❌ | `true` | Whether to post a PR comment |
| `security_scan` | ❌ | `true` | Whether to run the security scanner |

#### Action Outputs

| Output | Description |
|--------|-------------|
| `total_tokens` | Total token count across all changed files |
| `estimated_cost_usd` | Estimated AI review cost in USD |
| `risk_level` | Overall risk level: `OK`, `WARN`, or `BLOCK` |
| `security_findings` | Number of security risk findings |
| `comment_url` | URL of the posted PR comment |

---

### CLI Usage

```bash
# Analyse a PR
pr-cost-gate --token ghp_your_token --repo owner/repo --pr 42

# Use a different model
pr-cost-gate --token ghp_your_token --repo owner/repo --pr 42 --model claude-3-opus

# Override thresholds
pr-cost-gate --token ghp_your_token --repo owner/repo --pr 42 \
  --warn-threshold 0.50 --block-threshold 2.00

# Analyse without posting a comment
pr-cost-gate --token ghp_your_token --repo owner/repo --pr 42 --no-comment

# Skip security scan
pr-cost-gate --token ghp_your_token --repo owner/repo --pr 42 --no-security

# Verbose output (per-file breakdown in terminal)
pr-cost-gate --token ghp_your_token --repo owner/repo --pr 42 --verbose

# Use a custom config file
pr-cost-gate --token ghp_your_token --repo owner/repo --pr 42 \
  --config /path/to/my-config.yml
```

Using environment variables (useful for CI):

```bash
export GITHUB_TOKEN="ghp_your_token"
export GITHUB_REPOSITORY="owner/repo"
export PR_NUMBER="42"
export PCG_MODEL="claude-3-5-sonnet"

pr-cost-gate
```

---

## Installation

### From PyPI

```bash
pip install pr_cost_gate
```

### From Source

```bash
git clone https://github.com/your-org/pr_cost_gate.git
cd pr_cost_gate
pip install -e .
```

### Requirements

- Python 3.10+
- `PyGithub>=2.1.1`
- `tiktoken>=0.6.0`
- `PyYAML>=6.0.1`
- `requests>=2.31.0`

---

## Configuration Reference

Create `.pr_cost_gate.yml` in your repository root. All fields are optional — the defaults shown below are used when the file is absent or a field is omitted.

```yaml
# .pr_cost_gate.yml

# ---------------------------------------------------------------------------
# Model selection
# ---------------------------------------------------------------------------
model: gpt-4o

# ---------------------------------------------------------------------------
# Cost thresholds
# ---------------------------------------------------------------------------
thresholds:
  warn_usd: 1.00    # Add ⚠️ WARN badge above this cost
  block_usd: 5.00   # Exit 1 (BLOCK) above this cost

# ---------------------------------------------------------------------------
# Security scanning
# ---------------------------------------------------------------------------
security:
  enabled: true
  patterns:
    secrets: true             # API keys, tokens, passwords, private keys
    auth_changes: true        # Authentication/authorization code changes
    sql_injection: true       # Raw SQL string construction
    dangerous_functions: true # eval(), exec(), subprocess shell=True, etc.
    dependency_changes: true  # Package manifest modifications

# ---------------------------------------------------------------------------
# Comment settings
# ---------------------------------------------------------------------------
comment:
  post: true           # Whether to post a summary comment
  collapsible: true    # Wrap tables in <details> blocks
  post_when: always    # always | warn | block

# ---------------------------------------------------------------------------
# File exclusions
# ---------------------------------------------------------------------------
exclusions:
  paths:
    - "**/*.lock"
    - "**/vendor/**"
    - "**/__pycache__/**"
    - "**/*.min.js"
    - "**/*.min.css"
    - "**/node_modules/**"
    - "**/*.pb.go"
    - "**/*.pb.py"

# ---------------------------------------------------------------------------
# Token counting
# ---------------------------------------------------------------------------
tokens:
  max_per_file: 100000  # Cap per-file token count (prevents runaway costs)
  diff_only: true        # Count only +/- lines (not context lines)
```

### Model Selection

The `model` field selects the AI model pricing used for estimation. See the [pricing table](#ai-model-pricing-table) for costs.

```yaml
model: gpt-4o  # or: gpt-4-turbo, claude-3-5-sonnet, claude-3-opus, claude-3-haiku
```

### Cost Thresholds

Thresholds control when WARN and BLOCK states are triggered:

```yaml
thresholds:
  warn_usd: 1.00   # PR comment gets ⚠️ WARN badge; workflow continues (exit 0)
  block_usd: 5.00  # Workflow is halted (exit 1); downstream AI step is skipped
```

Set either value to `0` to disable that threshold entirely.

### Security Scanning

The security scanner checks every added diff line against 25+ regex rules:

```yaml
security:
  enabled: true          # Master switch
  patterns:
    secrets: true         # SECRET-001 through SECRET-009
    auth_changes: true    # AUTH-001 through AUTH-007
    sql_injection: true   # SQL-001 through SQL-005
    dangerous_functions: true  # EXEC-001 through EXEC-009
    dependency_changes: true   # DEP-001 through DEP-002
```

Security findings influence the risk level:
- **CRITICAL findings** → BLOCK (when `block_usd > 0`)
- **HIGH findings** → WARN
- MEDIUM/LOW findings → OK (informational only)

### Comment Settings

```yaml
comment:
  post: true           # Set to false to run analysis without commenting
  collapsible: true    # Collapses large tables in <details> blocks
  post_when: always    # 'always' | 'warn' | 'block'
```

`post_when` controls the minimum risk level required to post a comment:
- `always` — post for every PR regardless of findings (default)
- `warn` — only post when risk level is WARN or BLOCK
- `block` — only post when risk level is BLOCK

### File Exclusions

Use glob patterns to skip files from analysis:

```yaml
exclusions:
  paths:
    - "**/*.lock"          # All lockfiles
    - "**/vendor/**"       # Vendored dependencies
    - "docs/**"            # Documentation
    - "**/*.pb.go"         # Generated protobuf files
    - "frontend/dist/**"   # Built assets
```

Patterns use Unix shell glob conventions. `**` matches any number of path segments.

### Token Counting

```yaml
tokens:
  max_per_file: 100000  # Hard cap per file (prevents cost overestimates for generated files)
  diff_only: true        # Count only added/removed lines (recommended)
```

When `diff_only: true`, only lines starting with `+` or `-` in the unified diff are tokenised. This gives a more accurate estimate of what the AI reviewer would actually need to process.

When a file's token count hits `max_per_file`, it is capped and a ⚠️ indicator appears in the PR comment.

---

## AI Model Pricing Table

Pricing is based on published rates as of early 2024. Actual costs depend on model updates and your usage tier.

| Model | Input (per 1M tokens) | Output (per 1M tokens) | Notes |
|-------|----------------------|------------------------|-------|
| `gpt-4o` | $5.00 | $15.00 | OpenAI GPT-4o |
| `gpt-4-turbo` | $10.00 | $30.00 | OpenAI GPT-4 Turbo |
| `claude-3-5-sonnet` | $3.00 | $15.00 | Anthropic Claude 3.5 Sonnet |
| `claude-3-opus` | $15.00 | $75.00 | Anthropic Claude 3 Opus |
| `claude-3-haiku` | $0.25 | $1.25 | Anthropic Claude 3 Haiku |

> **Cost estimation methodology:** Input tokens are counted from the PR diff. Output tokens are estimated as 20% of input tokens (representing the model's review response). Total cost = `(input_tokens / 1M × input_price) + (output_tokens / 1M × output_price)`.

### Cost Examples

| PR Size | Tokens (approx.) | GPT-4o | Claude 3.5 Sonnet | Claude 3 Opus |
|---------|-----------------|--------|-------------------|---------------|
| Small (50 lines) | ~1,000 | $0.007 | $0.004 | $0.021 |
| Medium (500 lines) | ~10,000 | $0.070 | $0.042 | $0.210 |
| Large (2,000 lines) | ~40,000 | $0.280 | $0.168 | $0.840 |
| XL (10,000 lines) | ~200,000 | $1.40 | $0.84 | $4.20 |
| XXL (50,000 lines) | ~1,000,000 | $7.00 | $4.20 | $21.00 |

---

## Security Risk Patterns

The scanner checks diff hunks against the following rule categories:

### 🔑 Secrets (`secrets: true`)

| Rule ID | Description | Severity |
|---------|-------------|----------|
| SECRET-001 | Hardcoded API key (`api_key = "..."`) | CRITICAL |
| SECRET-002 | Hardcoded secret key (`secret_key = "..."`) | CRITICAL |
| SECRET-003 | Hardcoded password (`password = "..."`) | CRITICAL |
| SECRET-004 | Hardcoded auth token (`access_token = "..."`) | CRITICAL |
| SECRET-005 | Private key PEM material (`-----BEGIN ... PRIVATE KEY-----`) | CRITICAL |
| SECRET-006 | AWS credentials (`AWS_ACCESS_KEY_ID`, `AWS_SECRET_ACCESS_KEY`) | CRITICAL |
| SECRET-007 | Private key identifier (`private_key = "..."`) | HIGH |
| SECRET-008 | GitHub Personal Access Token (`ghp_`, `ghs_`, etc.) | CRITICAL |
| SECRET-009 | Database connection string | HIGH |

### 🔐 Auth Changes (`auth_changes: true`)

| Rule ID | Description | Severity |
|---------|-------------|----------|
| AUTH-001 | Auth decorator modified (`@login_required`, etc.) | HIGH |
| AUTH-002 | Auth check modified (`is_authenticated`, etc.) | HIGH |
| AUTH-003 | Security middleware changed | HIGH |
| AUTH-004 | Auth bypass detected (`skip_auth`, `disable_auth`) | CRITICAL |
| AUTH-005 | Wildcard CORS policy (`Access-Control-Allow-Origin: *`) | HIGH |
| AUTH-006 | Elevated privilege assignment (`role = "admin"`) | HIGH |
| AUTH-007 | Auth-sensitive filename changed (filename-based) | MEDIUM |

### 💉 SQL Injection (`sql_injection: true`)

| Rule ID | Description | Severity |
|---------|-------------|----------|
| SQL-001 | SQL query with string interpolation (`%s`, `{}`, f-string) | HIGH |
| SQL-002 | `execute()` with string formatting | HIGH |
| SQL-003 | Raw SQL call (`raw_query()`, `RawSQL()`) | MEDIUM |
| SQL-004 | SQL concatenated with user input | HIGH |
| SQL-005 | Cursor execute with `%` formatting | HIGH |

### ⚡ Dangerous Functions (`dangerous_functions: true`)

| Rule ID | Description | Severity |
|---------|-------------|----------|
| EXEC-001 | `eval()` usage | HIGH |
| EXEC-002 | `exec()` usage | HIGH |
| EXEC-003 | `__import__()` usage | MEDIUM |
| EXEC-004 | `subprocess` with `shell=True` | HIGH |
| EXEC-005 | `os.system()` usage | HIGH |
| EXEC-006 | `pickle.loads()` / `pickle.load()` | HIGH |
| EXEC-007 | `marshal.load` / `shelve.load` | MEDIUM |
| EXEC-008 | `yaml.load()` without SafeLoader | MEDIUM |
| EXEC-009 | `compile()` with `'exec'` mode | HIGH |

### 📦 Dependency Changes (`dependency_changes: true`)

| Rule ID | Description | Severity |
|---------|-------------|----------|
| DEP-001 | Dependency manifest file modified | MEDIUM |
| DEP-002 | New dependency added to manifest | LOW |

**Supported manifest files:** `requirements*.txt`, `setup.py`, `setup.cfg`, `pyproject.toml`, `Pipfile`, `Pipfile.lock`, `package.json`, `package-lock.json`, `yarn.lock`, `pnpm-lock.yaml`, `Gemfile`, `Gemfile.lock`, `go.mod`, `go.sum`, `Cargo.toml`, `Cargo.lock`, `composer.json`, `composer.lock`, `pom.xml`, `build.gradle`, `*.csproj`, `packages.config`

---

## Example PR Comment

When `pr_cost_gate` runs on a PR it posts a comment like this:

```
<!-- pr-cost-gate-comment -->

## 🤖 PR Cost Gate — *Add user authentication module*

| Field | Value |
|-------|-------|
| **Risk Level** | 🚫 **BLOCK** |
| **Model** | `gpt-4o` |
| **PR** | [#142](https://github.com/owner/repo/pull/142) |
| **Branch** | `feature/auth` → `main` |

### 💰 Cost Estimation

| Metric | Value |
|--------|-------|
| **Total Input Tokens** | `52,341` |
| **Estimated Output Tokens** | `10,468` |
| **Total Tokens** | `52,341` |
| **Estimated Cost** | `$0.4187 USD` |
| **Files Analysed** | `12` |
| **Files Skipped** | `3` |

### 📂 File Breakdown

<details>
<summary>Click to expand per-file breakdown (12 files)</summary>

| File | Status | Tokens | Cost (USD) | Capped |
|------|--------|-------:|----------:|:------:|
| `src/auth/middleware.py` | added | 18,234 | $0.1459 | |
| `src/auth/views.py` | added | 14,102 | $0.1128 | |
| `tests/test_auth.py` | added | 9,881 | $0.0790 | |
| ... | ... | ... | ... | |
| **Total** | | **52,341** | **$0.4187** | |

> **Skipped files** (3): `poetry.lock`, `yarn.lock`, `package-lock.json`

</details>

### 🔒 Security Findings

**3 finding(s) detected** — Highest severity: 🔴 CRITICAL

<details>
<summary>Click to expand security findings (3 issues)</summary>

| # | Rule | File | Risk | Description | Line |
|---|------|------|------|-------------|-----:|
| 1 | `SECRET-004` | `src/auth/views.py` | 🔴 CRITICAL | Possible hardcoded authentication token | 23 |
| 2 | `AUTH-004` | `src/auth/middleware.py` | 🔴 CRITICAL | Possible auth bypass detected | 47 |
| 3 | `DEP-001` | `requirements.txt` | 🟡 MEDIUM | Dependency manifest modified | — |

**Remediation Hints:**
- **`SECRET-004`**: Replace hardcoded tokens with environment variables or secrets manager references.
- **`AUTH-004`**: Confirm this is intentional — disabling authentication is a critical security risk.
- **`DEP-001`**: Run 'pip-audit' or equivalent to check for vulnerabilities in updated dependencies.

</details>

---
<sub>Generated by [pr-cost-gate](https://github.com/your-org/pr_cost_gate). Token counts are estimates; actual AI review costs may vary.</sub>
```

---

## Exit Codes

| Code | Meaning | When |
|------|---------|------|
| `0` | OK / WARN | Cost and security are within acceptable limits |
| `1` | BLOCK | Cost exceeds `block_usd` threshold, or CRITICAL security finding detected |
| `2` | Config/Arg Error | Missing required inputs, invalid config, or parse error |

---

## Environment Variables

All settings can be provided via environment variables, which override the config file but are overridden by CLI flags.

| Variable | Description |
|----------|-------------|
| `GITHUB_TOKEN` | GitHub API token (required) |
| `GITHUB_REPOSITORY` | Repository in `owner/name` format |
| `PR_NUMBER` | Pull request number |
| `PCG_MODEL` | AI model identifier |
| `PCG_WARN_THRESHOLD_USD` | WARN cost threshold in USD |
| `PCG_BLOCK_THRESHOLD_USD` | BLOCK cost threshold in USD |
| `PCG_CONFIG_PATH` | Path to `.pr_cost_gate.yml` |
| `PCG_POST_COMMENT` | `true` / `false` — post PR comment |
| `PCG_SECURITY_SCAN` | `true` / `false` — run security scan |
| `GITHUB_OUTPUT` | Set automatically by GitHub Actions for output variables |

---

## Development

### Setup

```bash
git clone https://github.com/your-org/pr_cost_gate.git
cd pr_cost_gate
python -m venv .venv
source .venv/bin/activate  # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
```

### Running Tests

```bash
# Run all tests
pytest

# Run with coverage
pytest --cov=pr_cost_gate --cov-report=term-missing

# Run a specific test module
pytest tests/test_analyzer.py -v

# Run tests matching a pattern
pytest -k "test_cost" -v
```

### Project Structure

```
pr_cost_gate/
├── __init__.py          # Package init, version
├── analyzer.py          # PR diff fetching, token counting, cost estimation
├── cli.py               # CLI entry point and orchestration
├── comment.py           # Markdown comment builder and GitHub poster
├── config.py            # Configuration loader and dataclasses
└── security.py          # Security risk pattern scanner

tests/
├── test_analyzer.py     # Tests for token counting and cost estimation
├── test_comment.py      # Tests for comment rendering and posting
├── test_config.py       # Tests for config loading and validation
└── test_security.py     # Tests for security pattern detection

action.yml               # GitHub Action metadata
Dockerfile               # Container image for GitHub Action runner
pyproject.toml           # Project metadata and dependencies
.pr_cost_gate.yml        # Example configuration file
README.md                # This file
```

### Architecture

```
CLI args + env vars
       │
       ▼
  cli.py (main)
       │
       ├─── config.py      load_config() + load_config_from_env()
       │                   → GateConfig
       │
       ├─── analyzer.py    PRAnalyzer.analyze()
       │                   → PRAnalysisResult (per-file token counts & costs)
       │
       ├─── security.py    SecurityScanner.scan_files()
       │                   → SecurityScanResult (findings per rule)
       │
       └─── comment.py     determine_risk_level()
                           CommentBuilder.build()
                           CommentPoster.post()
                           → risk_level, PostedComment
```

### Adding a New Security Rule

1. Add a `_Rule` instance to the appropriate rules list in `security.py`
2. Assign the next sequential rule ID (e.g. `SECRET-010`, `EXEC-010`)
3. Write a regex pattern, description, risk level, and remediation hint
4. Add a test case in `tests/test_security.py`

### Adding a New AI Model

1. Add the model identifier to `SUPPORTED_MODELS` in `config.py`
2. Add the pricing entry to `MODEL_PRICING` in `analyzer.py` as `(input_per_1m, output_per_1m)`
3. Add the tiktoken encoding mapping to `MODEL_ENCODING_MAP` in `analyzer.py`
4. Update the pricing table in this README
5. Update `action.yml` description for the `model` input

---

## Contributing

Contributions are welcome! Please:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/my-change`)
3. Make your changes with tests
4. Run the test suite (`pytest`)
5. Open a pull request

Please ensure:
- All tests pass
- New features have corresponding test coverage
- Code follows PEP 8 style
- Docstrings are included for public functions

---

## License

MIT License — see [LICENSE](LICENSE) for details.

---

<sub>Built with ❤️ to keep AI code review costs under control.</sub>
