# pr-cost-gate
pr_cost_gate is a GitHub Action and CLI tool that analyzes every pull request before expensive AI code review tools are triggered. It estimates token counts and projected AI review costs across changed files, flags files matching known security risk patterns (secrets, SQL injection, auth changes, etc.), and posts a structured summary comment direct
