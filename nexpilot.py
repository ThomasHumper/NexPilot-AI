python nexpilor.py /path/to/your/project


#!/usr/bin/env python3
"""
NexPilot AI
Autonomous Software Engineering Assistant

Features:
- Project discovery
- Python syntax analysis
- Security pattern detection
- TODO/FIXME tracking
- Code quality analysis
- Automated project reports
- Improvement recommendations

Standard library only.
"""

import ast
import json
import re
import argparse
import hashlib
from pathlib import Path
from datetime import datetime
from collections import Counter

VERSION = "1.0.0"

IGNORED = {
    ".git", ".venv", "venv", "__pycache__",
    "node_modules", "dist", "build", ".idea"
}

EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".java", ".go", ".rs", ".php", ".rb",
    ".cpp", ".c", ".cs"
}

SECURITY_RULES = [
    (
        "CRITICAL",
        "Hardcoded credential",
        re.compile(
            r"""(?i)\b(password|secret|api_key|access_token)\s*=\s*["'][^"']{6,}["']"""
        )
    ),
    (
        "HIGH",
        "Dynamic code execution",
        re.compile(r"\b(eval|exec)\s*\(")
    ),
    (
        "HIGH",
        "Potential unsafe shell execution",
        re.compile(r"\bshell\s*=\s*True")
    ),
    (
        "MEDIUM",
        "Weak cryptographic hash",
        re.compile(r"\b(md5|sha1)\s*\(")
    ),
    (
        "MEDIUM",
        "Disabled TLS verification",
        re.compile(r"\bverify\s*=\s*False")
    )
]


class Finding:
    def __init__(self, severity, category, message,
                 file, line=0):
        self.severity = severity
        self.category = category
        self.message = message
        self.file = str(file)
        self.line = line

    def to_dict(self):
        return {
            "severity": self.severity,
            "category": self.category,
            "message": self.message,
            "file": self.file,
            "line": self.line
        }


class NexPilot:

    def __init__(self, root):
        self.root = Path(root).resolve()
        self.findings = []
        self.stats = Counter()
        self.files = []
        self.project_hash = hashlib.sha256(
            str(self.root).encode()
        ).hexdigest()[:12]

    def discover(self):
        print("\n[1/5] Discovering project files...")

        for path in self.root.rglob("*"):
            if any(part in IGNORED for part in path.parts):
                continue

            if path.is_symlink() or not path.is_file():
                continue

            if path.suffix.lower() in EXTENSIONS:
                try:
                    if path.stat().st_size <= 1_000_000:
                        self.files.append(path)
                except OSError:
                    continue

        print(f"Found {len(self.files)} source files.")

    def analyze_python(self, path, source):
        try:
            tree = ast.parse(source)

            for node in ast.walk(tree):
                if isinstance(node, ast.FunctionDef):
                    self.stats["functions"] += 1

                    if len(node.body) > 50:
                        self.findings.append(Finding(
                            "MEDIUM",
                            "Code quality",
                            f"Large function: {node.name}",
                            path,
                            node.lineno
                        ))

                elif isinstance(node, ast.ClassDef):
                    self.stats["classes"] += 1

                elif isinstance(node, ast.ExceptHandler):
                    if node.type is None:
                        self.findings.append(Finding(
                            "MEDIUM",
                            "Code quality",
                            "Bare except clause detected",
                            path,
                            node.lineno
                        ))

        except SyntaxError as error:
            self.findings.append(Finding(
                "HIGH",
                "Python syntax error",
                error.msg,
                path,
                error.lineno or 0
            ))

    def analyze_file(self, path):
        try:
            source = path.read_text(
                encoding="utf-8",
                errors="replace"
            )
        except OSError:
            return

        self.stats["files"] += 1
        self.stats["lines"] += len(source.splitlines())

        if path.suffix == ".py":
            self.analyze_python(path, source)

        for number, line in enumerate(
            source.splitlines(), start=1
        ):
            stripped = line.strip()

            if "TODO" in stripped or "FIXME" in stripped:
                self.findings.append(Finding(
                    "LOW",
                    "Technical debt",
                    stripped[:160],
                    path,
                    number
                ))

            if len(line) > 120:
                self.stats["long_lines"] += 1

            for severity, category, pattern in SECURITY_RULES:
                if pattern.search(line):
                    self.findings.append(Finding(
                        severity,
                        "Security: " + category,
                        "Potential issue requiring manual review",
                        path,
                        number
                    ))

    def analyze(self):
        print("\n[2/5] Analyzing source code...")

        for index, path in enumerate(self.files, start=1):
            self.analyze_file(path)

            if index % 25 == 0:
                print(f"Analyzed {index} files...")

        print(f"Completed analysis of {len(self.files)} files.")

    def generate_recommendations(self):
        recommendations = []

        severities = Counter(
            finding.severity for finding in self.findings
        )

        if severities["CRITICAL"]:
            recommendations.append(
                "Immediately investigate potential hardcoded credentials."
            )

        if severities["HIGH"]:
            recommendations.append(
                "Review high-priority security and syntax findings."
            )

        if self.stats["long_lines"] > 10:
            recommendations.append(
                "Consider improving readability by shortening long lines."
            )

        if self.stats["functions"] == 0:
            recommendations.append(
                "Review project structure and add modular functions where appropriate."
            )

        if any(
            finding.category == "Technical debt"
            for finding in self.findings
        ):
            recommendations.append(
                "Review outstanding TODO and FIXME comments."
            )

        if not recommendations:
            recommendations.append(
                "No major issues detected by the current static checks. "
                "Consider adding automated tests and deeper security analysis."
            )

        return recommendations

    def generate_report(self):
        print("\n[3/5] Generating engineering report...")

        severities = Counter(
            finding.severity for finding in self.findings
        )

        report = {
            "tool": "NexPilot",
            "version": VERSION,
            "project_id": self.project_hash,
            "generated_at": datetime.now().isoformat(),
            "project": str(self.root),
            "statistics": dict(self.stats),
            "severity_summary": dict(severities),
            "findings": [
                finding.to_dict()
                for finding in self.findings
            ],
            "recommendations": self.generate_recommendations()
        }

        return report

    def save_reports(self, report):
        print("\n[4/5] Saving reports...")

        output = self.root / "nexpilot-reports"
        output.mkdir(exist_ok=True)

        json_path = output / "analysis.json"
        md_path = output / "analysis.md"

        json_path.write_text(
            json.dumps(report, indent=4),
            encoding="utf-8"
        )

        lines = [
            "# NexPilot Engineering Report",
            "",
            f"Generated: {report['generated_at']}",
            f"Project ID: {self.project_hash}",
            "",
            "## Statistics",
            "",
        ]

        for key, value in report["statistics"].items():
            lines.append(f"- **{key}:** {value}")

        lines += [
            "",
            "## Findings",
            ""
        ]

        if not self.findings:
            lines.append("No findings detected.")

        for finding in self.findings:
            lines.append(
                f"- **{finding.severity}** | "
                f"{finding.category} | "
                f"{finding.file}:{finding.line}"
            )
            lines.append(f"  - {finding.message}")

        lines += [
            "",
            "## Recommendations",
            ""
        ]

        for recommendation in report["recommendations"]:
            lines.append(f"- {recommendation}")

        md_path.write_text(
            "\n".join(lines),
            encoding="utf-8"
        )

        print(f"JSON report: {json_path}")
        print(f"Markdown report: {md_path}")

    def run(self):
        print("=" * 55)
        print("             NEXPILOT AI ENGINEERING")
        print(f"                  VERSION {VERSION}")
        print("=" * 55)

        if not self.root.is_dir():
            raise NotADirectoryError(
                f"Project directory does not exist: {self.root}"
            )

        self.discover()
        self.analyze()

        report = self.generate_report()

        self.save_reports(report)

        print("\n[5/5] Analysis completed.")
        print("=" * 55)
        print("PROJECT ANALYSIS SUMMARY")
        print("=" * 55)
        print(f"Files analyzed: {self.stats['files']}")
        print(f"Lines analyzed: {self.stats['lines']}")
        print(f"Total findings: {len(self.findings)}")

        for severity, count in Counter(
            f.severity for f in self.findings
        ).items():
            print(f"{severity}: {count}")

        print("\nRecommendations:")

        for item in report["recommendations"]:
            print(f"  - {item}")

        print("\nNexPilot analysis finished successfully!")


def main():
    parser = argparse.ArgumentParser(
        description="NexPilot AI Software Engineering Assistant"
    )

    parser.add_argument(
        "project",
        nargs="?",
        default=".",
        help="Path to the software project"
    )

    args = parser.parse_args()

    try:
        NexPilot(args.project).run()
    except (OSError, ValueError) as error:
        print(f"\nError: {error}")
        raise SystemExit(1)


if __name__ == "__main__":
    main()
