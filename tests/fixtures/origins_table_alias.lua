-- A table reaching a partly resolved join, mutated through an alias afterwards.
--
-- One branch binds `x` to the table itself and the other to a dynamic key, so the join
-- reports an `alternatives` set rather than a single reason. The write `t[1] = "new"`
-- then happens through `t`, which aliases the option inside that set.
--
-- The table option must not survive the write advertising the contents it held before.
-- Reporting `alternatives(table("old") | unknown:dynamic-key)` here would be a resolved
-- candidate that is wrong: when `flag` is true, `x` is `t`, and `t[1]` is "new".

local function sink(...) end

local function alias_stale(flag)
  local t = { "old" }
  local x
  if flag then
    x = t
  else
    x = math[flag]
  end
  t[1] = "new"
  sink(x)
end

alias_stale(true)
