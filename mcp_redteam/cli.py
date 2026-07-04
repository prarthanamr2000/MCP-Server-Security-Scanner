from __future__ import annotations

import argparse
import json
from pathlib import Path

from mcp_redteam.attackers.simulators import simulate_attack
from mcp_redteam.reporters.cvss import build_cvss_report, write_report
from mcp_redteam.scanners.static import scan_manifest


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="mcp-redteam")
    subparsers = parser.add_subparsers(dest="command", required=True)

    scan_parser = subparsers.add_parser("scan")
    scan_parser.add_argument("--config", required=True)
    scan_parser.add_argument("--output", default=None)

    attack_parser = subparsers.add_parser("attack")
    attack_parser.add_argument("--target", required=True)
    attack_parser.add_argument("--mode", required=True, choices=["tool-poison", "priv-escalation", "prompt-injection", "unauth"])

    report_parser = subparsers.add_parser("report")
    report_parser.add_argument("--output", required=True)
    report_parser.add_argument("--format", default="cvss", choices=["cvss"])
    report_parser.add_argument("--input", required=True)

    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.command == "scan":
        manifest_path = Path(args.config)
        manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
        report = scan_manifest(manifest)
        if args.output:
            Path(args.output).write_text(json.dumps(report, indent=2), encoding="utf-8")
        else:
            print(json.dumps(report, indent=2))

    if args.command == "attack":
        print(json.dumps(simulate_attack(args.mode, args.target), indent=2))

    if args.command == "report":
        payload = json.loads(Path(args.input).read_text(encoding="utf-8"))
        findings = payload.get("findings", []) if isinstance(payload, dict) else payload
        report = build_cvss_report(findings, title="MCP Security Findings")
        write_report(report, args.output)
        print(json.dumps(report, indent=2))


if __name__ == "__main__":
    main()
