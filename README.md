# MCP Server Security Scanner

Built a research-driven security scanner for MCP servers that evaluates agentic tool integrations for instruction override, over-privileged capabilities, trust-boundary abuse, and unauthenticated exposure. The project combines static analysis, adversarial simulation, and live server testing into a reusable workflow for MCP security review.

## Security research scope

This repository documents 5 findings from static analysis and real-server probing:

- 2 Critical findings
- 3 High findings
- Focus areas include tool-description injection, destructive filesystem access, and repository mutation surfaces exposed to agentic workflows

## What it does

- Scans MCP manifests for high-risk tool descriptions and capability abuse patterns
- Flags overprivileged scopes, trust-boundary escalation language, and unauthenticated routes
- Supports adversarial attack simulation modes for MCP-style abuse scenarios
- Produces CVSS-style JSON reports for triage and documentation

## Quick start

```bash
python -m pip install -e .
mcp-redteam scan --config sample_manifest.json --output report.json
mcp-redteam attack --target localhost:3000 --mode tool-poison
mcp-redteam report --input report.json --output findings.json
```

## Repository layout

- mcp_redteam/scanners: static analysis for manifests and configs
- mcp_redteam/attackers: adversarial server and attack simulation modules
- mcp_redteam/reporters: CVSS report generation
- findings/: structured research findings and attack notes
- docs/: STRIDE-style threat model and research notes

## Findings

- [findings/executive-summary.md](findings/executive-summary.md)
- [findings/tool-description-injection.md](findings/tool-description-injection.md)
- [findings/overprivileged-capabilities.md](findings/overprivileged-capabilities.md)
- [findings/unauthenticated-endpoint-exposure.md](findings/unauthenticated-endpoint-exposure.md)
- [findings/real-world-filesystem-mcp-test.md](findings/real-world-filesystem-mcp-test.md)
- [findings/real-world-github-mcp-test.md](findings/real-world-github-mcp-test.md)
- [findings/real-world-testing-results.md](findings/real-world-testing-results.md)
