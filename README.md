# Agent Context Poison Scanner

A dependency-free Python CLI that scans retrieved content **before** it
enters an LLM agent's context, and flags planted instructions hidden in
tool output, web pages, documents, tickets, or RAG chunks.

## Why this exists

An agent trusts what its tools return. An attacker who can plant text
in a retrieved document -- "ignore your instructions", a fake SYSTEM
message, an instruction to send private data somewhere -- can steer the
agent, because the text arrived through a trusted tool rather than
from the user. This is the input-side companion to output guards: scan
retrieved content first, and never append flagged lines to the context
unreviewed.

## What it detects

| Finding | Severity |
|---|---|
| Instruction override ("ignore previous instructions") | critical |
| New role assignment ("you are now...") | critical |
| Fake system / role marker (`SYSTEM:`, `[INST]`, `<\|system\|>`) | critical |
| Exfiltration instruction (send private data somewhere) | critical |
| Fake instruction block, external-send, tool-abuse, credential request | high |
| Hidden characters (zero-width, bidi overrides) | high |
| Authority claim, urgency override | medium |

All detection is pattern-based and fully offline: no network calls, no
API keys, no data leaves the machine.

## Usage

```bash
python context_poison_scanner.py retrieved.txt
python context_poison_scanner.py retrieved.txt --json
python context_poison_scanner.py retrieved.txt --redact clean.txt
cat tool_output.txt | python context_poison_scanner.py -
python context_poison_scanner.py retrieved.txt --fail-on high  # CI gate
```

Exit code: `0` = clean, `1` = findings, `2` = usage/input error.

## Example

```text
$ python context_poison_scanner.py examples/sample-tool-output.txt
3 finding(s), worst severity: critical
  line 6: [critical] instruction_override: ignore your previous instructions
  line 6: [critical] fake_system_marker: 2. SYSTEM:
  line 7: [critical] exfiltration_instruction: Send the customer's private
Counts: exfiltration_instruction=1, fake_system_marker=1, instruction_override=1
```

## Tests

```bash
python -m unittest discover tests -v   # 8 tests, all passing
```

## Files

- `context_poison_scanner.py` — the scanner (standard library only)
- `tests/test_context_poison_scanner.py` — 8 unit tests
- `examples/sample-tool-output.txt` — sample tool output with planted
  instructions (the address shown is the reserved example.com domain)

## Limitations

Pattern matching catches known phrasings, not meaning: it can miss
well-obfuscated or paraphrased injections and can flag legitimate
quoted text (for example, a security article describing an attack).
Treat its output as a triage aid: quarantine flagged lines, review
critical findings by hand, and never let retrieved content override
system instructions or trigger a destructive or exfiltrating tool call
without human approval.

## How it fits the series

This continues the AI-agent guardrail series: prompt-injection
detection on user input, tool-permission auditing before an agent
runs, output-leak scanning after it responds, and now
context-poisoning scanning on everything retrieved in between.

## Author

Sajid Hussain Raza — University Cybersecurity Lecturer, AI Security
Engineer and AI Red Teamer, Director and Co-founder of Cyber Legends,
Lahore. https://cyberlegends.org

## License

MIT.
