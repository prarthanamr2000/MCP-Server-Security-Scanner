from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional


def _normalize_text(value: str) -> str:
    return " ".join(re.sub(r"[^a-z0-9]+", " ", str(value).lower()).split())


def _load_rules(rules_config_path: Optional[Path | str] = None) -> Dict[str, Any]:
    default_rules_path = Path(__file__).resolve().parents[2] / "rules.json"
    path = Path(rules_config_path) if rules_config_path is not None else default_rules_path
    with path.open(encoding="utf-8") as handle:
        return json.load(handle)


def scan_manifest(manifest: Dict[str, Any], rules_config_path: Optional[Path | str] = None) -> Dict[str, Any]:
    rules = _load_rules(rules_config_path)
    injection_terms = rules.get("injection_terms", [])
    trust_boundary_terms = rules.get("trust_boundary_terms", [])
    overprivileged_rules = rules.get("overprivileged", {})
    unauthenticated_rules = rules.get("unauthenticated", {})
    findings: List[Dict[str, Any]] = []

    for tool in manifest.get("tools", []):
        description = _normalize_text(tool.get("description", ""))
        permissions = [_normalize_text(permission) for permission in (tool.get("permissions", []) or [])]

        if any(_normalize_text(term) in description for term in injection_terms):
            findings.append(
                {
                    "type": "tool_poisoning",
                    "severity": "critical",
                    "tool": tool.get("name", "unknown"),
                    "message": "Tool description contains instruction override or exfiltration language.",
                }
            )

        if any(_normalize_text(token) in description for token in trust_boundary_terms):
            findings.append(
                {
                    "type": "trust_boundary_violation",
                    "severity": "high",
                    "tool": tool.get("name", "unknown"),
                    "message": "Tool description suggests unsupported trust-boundary escalation or policy bypass.",
                }
            )

        required_permissions = {_normalize_text(permission) for permission in overprivileged_rules.get("required_permissions", [])}
        max_permissions = int(overprivileged_rules.get("max_permissions", 2))
        description_terms = overprivileged_rules.get("description_terms", [])
        if len(permissions) > max_permissions or (required_permissions <= set(permissions)) or any(_normalize_text(term) in description for term in description_terms):
            findings.append(
                {
                    "type": "overprivileged_scopes",
                    "severity": overprivileged_rules.get("severity", "high"),
                    "tool": tool.get("name", "unknown"),
                    "message": overprivileged_rules.get("message", "Tool declares a broad or destructive capability surface for agent execution."),
                }
            )

    unauthenticated = [endpoint for endpoint in manifest.get("endpoints", []) if endpoint.get("auth") is False]
    if unauthenticated:
        findings.extend(
            {
                "type": "unauthenticated_endpoint",
                "severity": unauthenticated_rules.get("severity", "critical"),
                "path": endpoint.get("path", "unknown"),
                "message": unauthenticated_rules.get("message", "Endpoint is exposed without authentication."),
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
