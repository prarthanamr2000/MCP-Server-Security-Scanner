from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict, List


SEVERITY_TO_CVSS = {"critical": 9.8, "high": 8.1, "medium": 6.1, "low": 3.9}


def build_cvss_report(findings: List[Dict[str, Any]], title: str = "Findings") -> Dict[str, Any]:
    return {
        "title": title,
        "summary": {
            "total": len(findings),
            "critical": sum(1 for item in findings if item.get("severity") == "critical"),
            "high": sum(1 for item in findings if item.get("severity") == "high"),
            "medium": sum(1 for item in findings if item.get("severity") == "medium"),
            "low": sum(1 for item in findings if item.get("severity") == "low"),
        },
        "findings": [
            {
                **item,
                "cvss": SEVERITY_TO_CVSS.get(str(item.get("severity", "low")).lower(), 3.9),
            }
            for item in findings
        ],
    }


def write_report(data: Dict[str, Any], output_path: str) -> None:
    Path(output_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
