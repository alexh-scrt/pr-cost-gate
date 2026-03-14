# pr_cost_gate

> **Stop paying $15–25 per PR** for AI code reviews you didn't mean to trigger — analyze diffs for token costs and security risks *before* the expensive models run.

[![GitHub Action](https://img.shields.io/badge/GitHub%20Action-ready-blue?logo=github)](#github-action-usage)
[![Python](https://img.shields.io/badge/python-3.10%2B-blue?logo=python)](#installation)
[![License: MIT](https://img.shields.io/badge/license-MIT-green)](LICENSE)

`pr_cost_gate` is a GitHub Action and CLI tool that inspects every pull request diff before expensive AI code review tools are triggered. It estimates token counts and projected costs across changed files, flags security risk patterns (hardcoded secrets, SQL injection, auth changes, and more), and posts a structured summary comment directly to the PR. Configure cost thresholds to emit a warning or block the workflow entirely.

---

## Quick Start

### GitHub Action

Add this step **before** your AI review step:

```yaml
# .github/workflows/pr-review.yml
steps:
  - name: PR Cost Gate
    uses: your-org/pr_cost_gate@v0.1.0
    with:
      github_token: ${{ secrets.GITHUB_TOKEN }}
      model: gpt-4o
      warn_usd: "1.00"
      block_usd: "5.00"

  - name: AI Code Review  # Only runs if cost gate passes
    uses: your-ai-review-action@latest
```

### CLI

```bash
pip install pr_cost_gate

pr-cost-gate --token ghp_yourtoken --repo owner/repo --pr 42
```

That's it. The tool will print a cost/risk summary to stdout and exit `0` (OK), `1` (BLOCK), or `2` (config error).

---

## Features

- **Token-accurate cost estimation** — Uses `tiktoken` to count tokens per file and calculates projected AI review costs for GPT-4o, GPT-4 Turbo, Claude 3.5 Sonnet, Claude 3 Opus, and Claude 3 Haiku.
- **Security risk pattern scanner** — Detects hardcoded secrets, auth/authorization changes, raw SQL construction, dangerous `eval`/`exec` usage, and dependency manifest modifications across the diff.
- **Configurable cost thresholds** — Set `warn_usd` and `block_usd` in `.pr_cost_gate.yml` to post warnings or halt the workflow with a non-zero exit code before the AI model is ever called.
- **Automatic PR comment** — Posts a collapsible Markdown summary table directly to the PR with flagged files, per-file cost breakdown, and actionable remediation hints.
- **Dual-mode operation** — Works as a zero-config GitHub Action with sensible defaults *and* as a standalone CLI tool for local pre-push checks.

---

## Installation

```bash
# From PyPI
pip install pr_cost_gate

# From source
git clone https://github.com/your-org/pr_cost_gate.git
cd pr_cost_gate
pip install -e .
```

**Requirements:** Python 3.10+

---

## Usage Examples

### CLI — basic check

```bash
pr-cost-gate \
  --token ghp_yourtoken \
  --repo owner/my-app \
  --pr 123
```

### CLI — override model and thresholds

```bash
pr-cost-gate \
  --token ghp_yourtoken \
  --repo owner/my-app \
  --pr 123 \
  --model claude-3-5-sonnet \
  --warn-usd 0.50 \
  --block-usd 3.00
```

### CLI — use a custom config file

```bash
pr-cost-gate \
  --token ghp_yourtoken \
  --repo owner/my-app \
  --pr 123 \
  --config path/to/my-config.yml
```

### GitHub Action — full example

```yaml
name: Gated AI Review
on:
  pull_request:
    types: [opened, synchronize]

jobs:
  review:
    runs-on: ubuntu-latest
    steps:
      - name: PR Cost Gate
        id: cost_gate
        uses: your-org/pr_cost_gate@v0.1.0
        with:
          github_token: ${{ secrets.GITHUB_TOKEN }}
          model: claude-3-5-sonnet
          warn_usd: "0.75"
          block_usd: "4.00"
          config_path: .pr_cost_gate.yml

      - name: Run AI Review
        # This step is skipped automatically if cost_gate exits 1 (BLOCK)
        uses: your-ai-review-action@latest
        with:
          token: ${{ secrets.OPENAI_API_KEY }}
```

### Example PR comment (posted automatically)

```
## 🔍 PR Cost Gate — WARN

**Estimated AI review cost:** $1.43  ⚠️ exceeds warn threshold ($0.75)
**Model:** claude-3-5-sonnet  |  **Total tokens:** 47,821

<details><summary>📂 File breakdown (12 files)</summary>

| File | Tokens | Est. Cost | Risk |
|------|--------|-----------|------|
| src/auth/middleware.py | 8,412 | $0.34 | 🔴 HIGH |
| src/models/user.py | 6,203 | $0.25 | 🟡 MEDIUM |
| requirements.txt | 1,104 | $0.04 | 🟡 MEDIUM |
| ... | | | |

</details>

### 🔒 Security Findings (3)
- `src/auth/middleware.py:42` — Auth decorator removed
- `src/models/user.py:88` — Raw SQL string construction
- `requirements.txt` — Dependency manifest modified
```

---

## Project Structure

```
pr_cost_gate/
├── pr_cost_gate/
│   ├── __init__.py      # Package init, version, top-level exports
│   ├── analyzer.py      # Token counting, cost estimation, PR diff fetching
│   ├── security.py      # Regex-based security risk pattern scanner
│   ├── comment.py       # Markdown comment builder and GitHub PR poster
│   ├── config.py        # Config loader and validator (.pr_cost_gate.yml)
│   └── cli.py           # CLI entry point and orchestration logic
├── tests/
│   ├── test_analyzer.py
│   ├── test_security.py
│   ├── test_config.py
│   ├── test_comment.py
│   └── test_cli.py
├── action.yml           # GitHub Action metadata and input definitions
├── .pr_cost_gate.yml    # Example/default configuration file
├── Dockerfile           # Minimal Python container for the Action runner
├── pyproject.toml       # Project metadata, dependencies, CLI entry point
└── README.md
```

---

## Configuration

Create a `.pr_cost_gate.yml` file in your repository root. All fields are optional — the defaults shown below apply if the file is absent.

```yaml
# .pr_cost_gate.yml

# AI model for cost estimation
# Options: gpt-4o | gpt-4-turbo | claude-3-5-sonnet | claude-3-opus | claude-3-haiku
model: gpt-4o

# Cost thresholds
thresholds:
  warn_usd: 1.00    # Post a warning comment but allow workflow to continue
  block_usd: 5.00   # Exit with code 1 to halt downstream workflow steps

# Comment behavior
comment:
  post_when: always   # Options: always | warn_or_block | block_only | never
  collapse_file_list: true

# Token counting
tokens:
  diff_only: true           # Count only changed lines (true) or full file (false)
  max_tokens_per_file: 0    # 0 = no cap
  exclude_patterns:         # Glob patterns for files to skip
    - "*.lock"
    - "dist/**"
    - "*.min.js"

# Security scanning
security:
  enabled: true
  patterns:
    secrets: true
    auth_changes: true
    sql_injection: true
    dangerous_functions: true
    dependency_manifests: true
```

### Model Pricing Reference

| Model | Input (per 1M tokens) | Output (per 1M tokens) |
|---|---|---|
| `gpt-4o` | $5.00 | $15.00 |
| `gpt-4-turbo` | $10.00 | $30.00 |
| `claude-3-5-sonnet` | $3.00 | $15.00 |
| `claude-3-opus` | $15.00 | $75.00 |
| `claude-3-haiku` | $0.25 | $1.25 |

### GitHub Action Inputs

| Input | Required | Default | Description |
|---|---|---|---|
| `github_token` | Yes | `${{ github.token }}` | Token to read diffs and post comments |
| `model` | No | `gpt-4o` | AI model for cost estimation |
| `warn_usd` | No | `1.00` | Warning threshold in USD |
| `block_usd` | No | `5.00` | Blocking threshold in USD |
| `config_path` | No | `.pr_cost_gate.yml` | Path to config file |

### Environment Variables

All CLI flags can also be set via environment variables — useful in the GitHub Action context:

| Variable | Equivalent flag |
|---|---|
| `GITHUB_TOKEN` | `--token` |
| `GITHUB_REPOSITORY` | `--repo` |
| `PR_NUMBER` | `--pr` |
| `PR_COST_GATE_MODEL` | `--model` |
| `PR_COST_GATE_WARN_USD` | `--warn-usd` |
| `PR_COST_GATE_BLOCK_USD` | `--block-usd` |

---

## Exit Codes

| Code | Meaning |
|---|---|
| `0` | OK or WARN — workflow continues |
| `1` | BLOCK — cost or risk threshold exceeded; halts downstream steps |
| `2` | Configuration or argument error |

---

## License

MIT — see [LICENSE](LICENSE) for details.

---

*Built with [Jitter](https://github.com/jitter-ai) - an AI agent that ships code daily.*
