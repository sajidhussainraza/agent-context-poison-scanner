#!/usr/bin/env python3
"""Scan retrieved content before it enters an LLM agent's context.

An agent trusts what its tools return: web pages, documents, tickets,
and database rows. Attackers plant instructions in that retrieved
content -- "ignore your instructions", a fake SYSTEM message, a hidden
instruction to exfiltrate data -- and the agent follows them because
the text arrived through a trusted tool, not from the user.

This scanner is the input-side guardrail for retrieved content: run it
on tool output or RAG chunks *before* they are appended to the agent's
context. It is pattern-based and fully offline (standard library only);
no data leaves the machine.

Usage:
    python context_poison_scanner.py retrieved.txt
    python context_poison_scanner.py retrieved.txt --json
    python context_poison_scanner.py retrieved.txt --redact clean.txt
    cat tool_output.txt | python context_poison_scanner.py -
    python context_poison_scanner.py retrieved.txt --fail-on high

Exit codes: 0 = clean, 1 = findings, 2 = usage/input error.
"""

import argparse
import json
import re
import sys
from dataclasses import dataclass

SEVERITY_RANK = {"low": 0, "medium": 1, "high": 2, "critical": 3}

# (name, severity, regex) -- case-insensitive, applied per line.
PATTERNS = [
    ("instruction_override", "critical",
     r"\b(ignore|disregard|override|forget)\b.{0,40}\b"
     r"(previous|prior|original|system|your|all)\b.{0,20}\b"
     r"(instructions?|rules?|prompts?|guidelines?|constraints?)\b"),
    ("new_role_assignment", "critical",
     r"\b(you are now|from now on,? you are|act as|pretend (to be|you are)|"
     r"roleplay as|assume the role of)\b"),
    ("fake_system_marker", "critical",
     r"^\s*(?:\d+[.)]\s*)?(\[SYSTEM\]|SYSTEM:|Assistant:|User:|"
     r"<\|system\|>|\[INST\]|###\s*(System|Instruction))(?![A-Za-z])"),
    ("fake_instruction_block", "high",
     r"\b(new instructions?|updated instructions?|developer message|"
     r"system update|hidden instructions?)\b\s*[:\-]"),
    ("exfiltration_instruction", "critical",
     r"\b(send|forward|post|upload|email|exfiltrate)\b.{0,40}\b"
     r"(password|secret|api[-_ ]?key|token|credential|private|"
     r"confidential|user data|conversation)\b"),
    ("external_send_instruction", "high",
     r"\b(send|post|upload)\b.{0,30}\b(to|at)\b\s+"
     r"(https?://|[\w.+-]+@[\w-]+\.[\w.-]+)"),
    ("tool_abuse_instruction", "high",
     r"\b(run|execute|delete|drop|truncate|transfer|pay)\b.{0,30}\b"
     r"(shell|command|file|table|database|payment|money)\b"),
    ("credential_request", "high",
     r"\b(enter|provide|share|reveal|paste)\b.{0,25}\b"
     r"(your )?(password|api[-_ ]?key|secret|token|otp|verification code)\b"),
    ("authority_claim", "medium",
     r"\b(as (an? )?(admin|developer|system|superuser)|"
     r"authorized by|approved by (the )?(system|developer|admin))\b"),
    ("urgency_override", "medium",
     r"\b(urgent|immediately|do not (ask|verify|confirm)|"
     r"skip (verification|confirmation|approval)|no need to (ask|verify))\b"),
]

# Invisible / direction-override characters often used to hide text.
HIDDEN_CHARS = {
    "\u200b": "zero-width space",
    "\u200c": "zero-width non-joiner",
    "\u200d": "zero-width joiner",
    "\ufeff": "byte-order mark",
    "\u202a": "bidi embedding (LTR)",
    "\u202b": "bidi embedding (RTL)",
    "\u202c": "bidi pop directional formatting",
    "\u202d": "bidi override (LTR)",
    "\u202e": "bidi override (RTL)",
    "\u2066": "isolate (LTR)",
    "\u2067": "isolate (RTL)",
    "\u2069": "isolate pop",
}


@dataclass
class Finding:
    line: int
    severity: str
    kind: str
    text: str

    def to_dict(self):
        return {"line": self.line, "severity": self.severity,
                "kind": self.kind, "text": self.text}


def scan_text(text):
    """Return a list of Finding objects for *text*."""
    findings = []
    for lineno, line in enumerate(text.splitlines(), start=1):
        for name, severity, pattern in PATTERNS:
            match = re.search(pattern, line, re.IGNORECASE)
            if match:
                findings.append(Finding(lineno, severity, name,
                                        match.group(0).strip()))
        for char, label in HIDDEN_CHARS.items():
            if char in line:
                findings.append(Finding(lineno, "high",
                                        "hidden_character",
                                        f"hidden character: {label}"))
                break  # one hidden-character finding per line is enough
    return findings


def summarise(findings):
    if not findings:
        return {"findings": 0, "worst_severity": None, "counts": {}}
    counts = {}
    for finding in findings:
        counts[finding.kind] = counts.get(finding.kind, 0) + 1
    worst = max(findings, key=lambda f: SEVERITY_RANK[f.severity])
    return {"findings": len(findings),
            "worst_severity": worst.severity, "counts": counts}


def redact_text(text, findings):
    """Return *text* with every flagged line replaced by a placeholder."""
    flagged = {f.line for f in findings}
    lines = text.splitlines()
    return "\n".join(
        "[REDACTED: flagged by context-poison scanner]" if i + 1 in flagged
        else line for i, line in enumerate(lines)
    ) + ("\n" if text.endswith("\n") else "")


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Scan retrieved content for planted agent instructions.")
    parser.add_argument("path", help="file to scan, or - for stdin")
    parser.add_argument("--json", action="store_true",
                        help="print the report as JSON")
    parser.add_argument("--redact", metavar="OUT",
                        help="write a copy with flagged lines redacted")
    parser.add_argument("--fail-on", choices=list(SEVERITY_RANK),
                        help="exit 1 also when a finding reaches this "
                             "severity (default: any finding exits 1)")
    args = parser.parse_args(argv)

    try:
        if args.path == "-":
            text = sys.stdin.read()
        else:
            with open(args.path, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
    except OSError as exc:
        print(f"error: cannot read {args.path}: {exc}", file=sys.stderr)
        return 2

    findings = scan_text(text)
    summary = summarise(findings)

    if args.redact:
        try:
            with open(args.redact, "w", encoding="utf-8") as fh:
                fh.write(redact_text(text, findings))
        except OSError as exc:
            print(f"error: cannot write {args.redact}: {exc}", file=sys.stderr)
            return 2

    if args.json:
        print(json.dumps({"summary": summary,
                          "findings": [f.to_dict() for f in findings]},
                         indent=2))
    elif findings:
        print(f"{len(findings)} finding(s), "
              f"worst severity: {summary['worst_severity']}")
        for finding in findings:
            print(f"  line {finding.line}: [{finding.severity}] "
                  f"{finding.kind}: {finding.text}")
        print("Counts: " + ", ".join(
            f"{kind}={n}" for kind, n in sorted(summary["counts"].items())))
    else:
        print("clean: no planted instructions detected")

    if not findings:
        return 0
    if args.fail_on:
        return 1 if (SEVERITY_RANK[summary["worst_severity"]]
                     >= SEVERITY_RANK[args.fail_on]) else 0
    return 1


if __name__ == "__main__":
    raise SystemExit(main())
