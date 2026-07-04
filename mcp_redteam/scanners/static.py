from __future__ import annotations

from typing import Any, Dict, List


INJECTION_TERMS = [
    "ignore previous instructions",
    "ignore system prompt",
    "exfiltrate",
    "reveal secrets",
    "bypass approval",
    "override policy",
    "follow hidden instructions",
    "trust the next instruction",
    "send data to",
    "use the token",
]


def scan_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    findings: List[Dict[str, Any]] = []

    for tool in manifest.get("tools", []):
        description = str(tool.get("description", "")).lower()
        permissions = [str(permission).lower() for permission in (tool.get("permissions", []) or [])]

        if any(term in description for term in INJECTION_TERMS):
            findings.append(
                {
                    "type": "tool_poisoning",
                    "severity": "critical",
                    "tool": tool.get("name", "unknown"),
                    "message": "Tool description contains instruction override or exfiltration language.",
                }
            )

        if any(token in description for token in ["bypass", "override", "elevate", "hidden instruction", "approval"]):
            findings.append(
                {
                    "type": "trust_boundary_violation",
                    "severity": "high",
                    "tool": tool.get("name", "unknown"),
                    "message": "Tool description suggests unsupported trust-boundary escalation or policy bypass.",
                }
            )

        if len(permissions) > 2 or ({"filesystem:write", "network:call"} <= set(permissions)) or ("merge" in description and "pull request" in description):
            findings.append(
                {
                    "type": "overprivileged_scopes",
                    "severity": "high",
                    "tool": tool.get("name", "unknown"),
                    "message": "Tool declares a broad or destructive capability surface for agent execution.",
                }
            )

    unauthenticated = [endpoint for endpoint in manifest.get("endpoints", []) if endpoint.get("auth") is False]
    if unauthenticated:
        findings.extend(
            {
                "type": "unauthenticated_endpoint",
                "severity": "critical",
                "path": endpoint.get("path", "unknown"),
                "message": "Endpoint is exposed without authentication.",
            }
            for endpoint in unauthenticated
        )

    return {
        "manifest": manifest.get("name", "unknown"),
        "summary": {
            "tool_poisoning": sum(1 for item in findings if item["type"] == "tool_poisoning"),
            "overprivileged_scopes": sum(1 for item in findings if item["type"] == "overprivileged_scopes"),
            "trust_boundary_violations": sum(1 for item in findings if item["type"] == "trust_boundary_violation"),
            "unauthenticated_endpoints": sum(1 for item in findings if item["type"] == "unauthenticated_endpoint"),
        },
        "findings": findings,
    }
