# Active checkpoint: independent customer transfer

Lane: customer validation. Target: determine whether the exact Lua 5.1 LNUM32
candidate can support real firmware investigation without implementation guidance.

## Inputs

- candidate evidence index and macOS/Linux archives from CI run `32919471567`;
- one different TP-Link firmware version or investigation objective;
- one outside-human trial using different-vendor Lua firmware;
- the workflows in [`LUA51-LNUM32-CANDIDATE.md`](LUA51-LNUM32-CANDIDATE.md).

Each trial records the candidate archive and binary SHA-256, firmware context, commands
attempted, workflow outcomes, incorrect answers, blocking friction, and minimized
redistributable reproductions. Private firmware and extracted secrets stay outside this
repository.

## Acceptance

Both investigators must be able to inventory files, confirm profile/layout identity,
search constants, inspect symbolic callees and unresolved reasons, inspect argument
origins, follow closure captures, and preserve deterministic machine output.

A silent or incorrect factual answer blocks acceptance. It becomes a minimized public
fixture and a product fix before the candidate is rebuilt. Usability feedback blocks
only when it prevents a required workflow; other friction feeds the product backlog.

No new release, attestation, gate, schema, or orchestration mechanism is part of this
checkpoint.

## Exit

After both trials satisfy the acceptance criteria, the next sprint may promote only the
exact `lua5.1-lnum32` target and publish its verified artifacts. The base `lua5.1`
dialect and all other targets remain experimental.
