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

-- The mutated register can itself hold a set of reaching definitions. The write then goes
-- through whichever one the branch selected, so every table option of that set is a
-- possible alias. Comparing the candidate against the set as a whole matches only a
-- candidate sharing its exact shape, which these two cases deliberately do not.

local function alias_through_joined_base(flag)
  local t, other = { "old" }, { "other" }
  local x, b
  if flag then x = t else x = math[flag] end
  if flag then b = t else b = other end
  b[1] = "new"
  sink(x)
end

-- No unknown anywhere, so this case does not depend on a partly resolved join at all. It
-- also pins precision in the other direction: `third` is never an alias of `b` here, so
-- the option holding it must survive the write.
local function alias_two_sets(flag, flag2)
  local t, other, third = { "old" }, { "other" }, { "third" }
  local x, b
  if flag then x = t else x = third end
  if flag2 then b = t else b = other end
  b[1] = "new"
  sink(x)
end

alias_through_joined_base(true)
alias_two_sets(true, true)
