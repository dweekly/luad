# Distinguish caller argument fields in text

Fresh as of 2026-11-22.

The two observed argparse suggestion calls pass the options or commands field of
parameter zero. Both currently print as field. Render a direct string-keyed
field of a parameter owned by the caller as param#N["key"], with the shared
byte-string renderer. Limit the compact view to keys of at most 64 original
bytes. Keep complex fields compact. Preserve the argument JSON and JSONL.

Edit the caller text renderer, its CLI regressions, the machine reference, agent
skill, changelog and README index. Build with `cargo build -p luad-cli`, then run
`cargo test -p luad-oracle --test test_callers_lua51`. Assert distinct fields,
escaped bytes and fallback for nested and oversized keys. Recheck the two real
stripped argparse call sites. Stop after the focused test, origins gate and
aggregate check pass.
