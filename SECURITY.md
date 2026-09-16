# Security policy

## Status and supported versions

`luad` is pre-release software. Only the current `main` branch is considered for security fixes. No released version is currently designated production-supported.

The project is intended to process untrusted Lua bytecode, but all dialects remain
experimental until their exact public and release gates pass. Do not rely on `luad`
as the sole control for accepting, rejecting, or characterizing hostile code. See
the evidence boundaries in the [product roadmap](ROADMAP.md), [active sprint](docs/NEXT-SPRINT.md), and
[machine-interface contract](docs/MACHINE-INTERFACE.md).

The planned 1.0 matrix contains two separate claims: the exact OpenWrt-derived Lua
5.1.5 LNUM32 profile `lua5.1-lnum32`, and one exact stock PUC Lua 5.1.5 64-bit layout
`lua5.1`. Stock PUC Lua 5.4.9 is a post-1.0 candidate, not a planned 1.0 target. The
canonical profile and layout identities live in the
[frozen version-1 boundary](docs/RELEASING.md#frozen-version-1-boundary). This future
matrix does not designate any current code or candidate as security-supported. After
release, this section must be replaced with the actual supported tool versions and
their security-fix window.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting or Security Advisory facility for
`dweekly/luad` when available. Include the affected commit, a minimal reproducer,
the command and options, expected and observed behavior, and the security impact.

Do not place exploit artifacts or sensitive details in a public issue. If private reporting is unavailable, open a minimal public issue requesting a private contact channel without disclosing the vulnerability.

## Threat model

In scope:

- panics, memory exhaustion, excessive CPU, or unbounded output from crafted chunks;
- operand misdecoding or validation that incorrectly blesses hostile input;
- terminal, JSON, or DOT injection through bytecode strings or future overlays;
- unsafe-code undefined behavior (mitigated by workspace-level `unsafe_code = "forbid"` across all shipped packages with negative-control proof);
- unhandled malformed or adversarial inputs across detection, parsing, disassembly, validation, CFG, and xref analysis (continuously exercised by an 8-target fuzz smoke suite with pinned seed corpora);
- evidence claims that materially misrepresent verified behavior;
- supply-chain risks in scripts that download oracle compilers.

Out of scope unless separately sandboxed:

- executing untrusted Lua source or bytecode;
- security of external Lua compilers and runtimes;
- research notes, databases, or orchestration systems maintained by callers.

`luad` should not execute analyzed bytecode. Tests invoking an external compiler must operate only on trusted source and make that trust boundary explicit.
