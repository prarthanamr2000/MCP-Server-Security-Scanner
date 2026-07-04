# Finding 005 — High: GitHub MCP Server Exposes Repository-Mutation Capability to Agentic Workflows

- Severity: HIGH
- Target: @modelcontextprotocol/server-github
- Test method: connected over MCP stdio and enumerated the live tool catalog using the real server implementation

## Summary

The GitHub server exposes tool actions that can create or update files, create repositories, open pull requests, merge pull requests, and manage review workflows. These capabilities are ordinary in a developer environment, but in an agent-mediated setting they represent a high-impact trust boundary because they can change repository state without a human-in-the-loop approval step.

## Why it matters

This is a serious control issue for agentic systems because a misdirected or overly trusted model can trigger repository mutation, branch creation, or merge activity. Once that capability is exposed, the security posture depends heavily on prompt isolation, approval handling, and scoped permissions.

## Remediation

- Require human confirmation for destructive repository actions
- Separate read-only browsing from mutation capabilities
- Enforce repository-scoped access and branch protections
