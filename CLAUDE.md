# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

# Code Reliability Rules

These rules are mandatory for all generated code. Violations require a comment
at the violation site explaining why the alternative is worse.

## Rules

**1. Linear control flow.** Max 3 nesting levels. Guard clauses at top, happy
path below. If nesting hits 3, extract a function or invert and return early.

**2. Bound every iteration.** Every loop, retry, poll, pagination, and
recursive call gets an explicit enforced maximum. When the bound is hit,
handle it — never silently continue.

**3. Own your resources.** Every resource opened gets closed on the happy path
AND every error path. Use language-native resource management (`with`, `using`,
`defer`, RAII, `finally`).

**4. One function, one job, ≤40 lines.** Describable in one sentence without
"and." Measure logic lines only (exclude blanks, comments, signatures,
closing braces).

**5. Narrow state.** Smallest possible scope. Default immutable. Pass
dependencies through parameters, not globals or class-level state. No
module-level mutable state.

**6. Validate at boundaries.** Parse external input into typed domain objects
at entry points (Zod, Pydantic, schema validation). Internal functions trust
validated types. Use assertions for internal invariants that should never fail.

**7. Never swallow errors.** Every error is propagated, recovered from with
explicit logic, or logged with context. No empty catch blocks. No discarded
error returns. If ignoring a return value, annotate why.

**8. Surface side effects.** I/O, mutations, network calls, and DB writes
must be obvious at the call site. Separate pure computation from effectful
operations. If a function has side effects, its name says so.

**9. Dependencies are liabilities.** Justify each import. Pin versions. If
<100 lines of code avoids a large dependency, write it. Check maintenance
status before suggesting any package.

**10. Warnings are errors.** All type checking, linting, and static analysis
at strictest settings. Zero warnings. No `@ts-ignore` or `type: ignore`
without a justifying comment.

**11. Every line explainable.** No cargo-culted patterns. No code you can't
justify line by line. Prefer boring over clever. Mark uncertainty with `TODO`.

**12. Tests first.** Write tests before or alongside implementation. Cover:
happy path, at least one edge case, at least one error path, and any
boundary conditions from requirements.

## Self-Review Before Presenting Code

- No function exceeds 40 logic lines
- No nesting exceeds 3 levels
- Every loop/retry has an explicit bound
- Every resource opened is closed on all paths
- Every error handled — none swallowed
- External input validated at boundaries
- Side effects visible at call sites
- No unjustified dependencies
- Every line explainable
- Tests cover happy path, edge cases, and errors

## Severity

- **Critical path** (auth, payments, data): All 12, no exceptions.
- **Production services**: All 12, pragmatic documented exceptions.
- **Internal tools/scripts**: Rules 1–4, 7, 10, 11.
- **Prototypes**: Rules 2, 7, 11. Rewrite before production.

## Project Overview

`greynoise-lookup` — a CLI tool for IP, subnet, and ASN threat research. Takes a list of targets from an input file, performs reverse DNS lookups and GreyNoise community API queries, and writes structured results to CSV.

## How to Run

```bash
# Set up
python3 -m venv .venv
source .venv/bin/activate
pip install -e ".[dev]"

# Run the CLI
greynoise-lookup -i iplist.txt -o results.csv
greynoise-lookup --dry-run -i iplist.txt
greynoise-lookup -v --max-ips 100 -i iplist.txt

# Or run as module
python -m greynoise_lookup -i iplist.txt

# Run tests
pytest
pytest --cov=greynoise_lookup --cov-report=term-missing
```

## Architecture

```
src/greynoise_lookup/
├── models.py    # EntryType enum, ClassifiedEntry, LookupResult (frozen dataclasses)
├── parser.py    # classify_entry(), expand_subnet(), resolve_asn_to_networks(), parse_input_file()
├── lookup.py    # reverse_dns(), query_greynoise() with retry/backoff, process_ip()
├── writer.py    # write_results() via csv.DictWriter, build_summary(), print_summary()
├── cli.py       # argparse CLI, logging setup, orchestration (main entry point)
└── __main__.py  # python -m support
```

**Data flow**: input file -> parser (classify + expand) -> lookup (DNS + GreyNoise per IP) -> writer (CSV + summary)

Three input types supported:
1. **IP** — single IPv4/IPv6 address, direct PTR + GreyNoise lookup
2. **Subnet** — CIDR notation, expanded to individual IPs
3. **ASN** — resolved to netblocks via Shadowserver API, then expanded

## Configuration

- **API key**: optional, via `GREYNOISE_API_KEY` in `.env` file (see `.env.example`)
- **Dependencies**: `dnspython`, `requests`, `python-dotenv` (pinned in `pyproject.toml`)
- **Dev deps**: `pytest`, `pytest-cov`, `responses`

## Key Design Decisions

- ASN detection uses regex `^asn?\d+$` (case-insensitive) to avoid false positives
- All API calls have retry with exponential backoff (max 3 attempts)
- Subnet/ASN expansion bounded by `--max-ips` flag (default 10,000)
- Rate limiting via configurable sleep between GreyNoise API calls
- All file I/O uses context managers; CSV via `csv.DictWriter`
