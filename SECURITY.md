# Security policy

## Status and supported versions

`luad` is pre-release software. Only the current `main` branch is considered for security fixes. No released version is currently designated production-supported.

The project is intended to process untrusted Lua bytecode, but a correctness review has identified critical decoding and validation defects. Until the remediation gates in [ROADMAP.md](ROADMAP.md) pass, do not rely on `luad` as the sole control for accepting, rejecting, or characterizing hostile code.

## Reporting a vulnerability

Use GitHub's private vulnerability-reporting or Security Advisory facility for `dew/luad` when available. Include the affected commit, a minimal reproducer, the command and options, expected and observed behavior, and the security impact.

Do not place exploit artifacts or sensitive details in a public issue. If private reporting is unavailable, open a minimal public issue requesting a private contact channel without disclosing the vulnerability.

## Threat model

In scope:

- panics, memory exhaustion, excessive CPU, or unbounded output from crafted chunks;
- operand misdecoding or validation that incorrectly blesses hostile input;
- terminal, JSON, or DOT injection through bytecode strings or future overlays;
- unsafe-code undefined behavior;
- evidence claims that materially misrepresent verified behavior;
- supply-chain risks in scripts that download oracle compilers.

Out of scope unless separately sandboxed:

- executing untrusted Lua source or bytecode;
- security of external Lua compilers and runtimes;
- research notes, databases, or orchestration systems maintained by callers.

`luad` should not execute analyzed bytecode. Tests invoking an external compiler must operate only on trusted source and make that trust boundary explicit.
