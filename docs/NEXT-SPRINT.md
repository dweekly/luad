# Delivery checkpoint

Fresh as of: 2026-10-22.

No implementation is authorized by this checkpoint. Select one bounded outcome from
[`ROADMAP.md`](../ROADMAP.md) and commit its contract before editing production code.

The next core outcome is Lua 5.1 call-frame value lifetime across callee, argument-origin
and capture analysis. Its contract must preserve explicit results/live locals, invalidate
stale temporary-register facts, and exercise structurally valid public call-tail controls
without executing the crafted bytes. Retain the accepted module-initialization controls
as prerequisites; the new cross-chunk interaction must not recreate a stale target.

The firmware consumer owns its independent uncertainty/call-path repairs in its private
repository. Do not substitute those semantics or private samples for public core gates.
Qualification follows [`DEVELOPMENT-WORKFLOW.md`](DEVELOPMENT-WORKFLOW.md) and
[`ROADMAP-1.0.md`](ROADMAP-1.0.md); roadmap direction alone promotes no target or interface.
