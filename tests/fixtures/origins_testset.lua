-- TESTSET is the one Lua 5.1 instruction whose sole effect is a register write that one of
-- its outgoing edges skips. These are the `or` and `and` idioms over locals, which is where
-- luac emits it; the `or`-with-a-constant-default form compiles to TEST instead and is
-- covered by origins.lua.

local function pick_either(primary, secondary)
  local chosen = primary or secondary
  sink(chosen)
end

local function guarded_literal(flag)
  local chosen = flag and "enabled"
  sink(chosen)
end

local function command_with_fallback(params, fallback)
  local dir = params.dir or fallback
  sink("mkdir -p " .. dir .. "/sub")
end

local function chained(a, b, c)
  local chosen = a or b or c
  sink(chosen)
end

return { pick_either, guarded_literal, command_with_fallback, chained }
