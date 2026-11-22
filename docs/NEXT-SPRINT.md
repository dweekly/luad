# Hand off a verified trial input bundle

Fresh as of 2026-11-22.

The moderator's checksum manifest includes itself and fails verification on a
fresh build. Generate checksums for the payload only, preserving all 15 compiled
inputs. Include the LuCI license and attribution with the handoff.

Edit scripts/trials/build_inputs.sh, add a focused transfer regression under
scripts/trials, and update docs/TRIALS.md, the README index and changelog.
Run `bash scripts/trials/test_inputs.sh STOCK_LUAC LNUM32_LUAC`. It must build
with the actual compilers, verify every payload after transfer, and reject
a changed byte. Stop after a local trial archive verifies after extraction.
