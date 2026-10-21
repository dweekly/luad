-- Captured registers the parent writes after building the closure. Every write is
-- visible in the parent prototype, so the set of definitions that can reach the
-- closure is finite; the closure may run before or after any of them, so the set is
-- not a claim about a path. Each function here isolates one shape of that set.

-- The parent writes the captured register once after the closure is built.
local function one_write_after_the_closure(name)
  local prefix = "/etc/config"
  local run = function()
    sink("cat " .. prefix)
  end
  prefix = "/tmp"
  return run
end

-- Two writes after the closure, so the set has three members including the value
-- the register held when the closure was built.
local function two_writes_after_the_closure()
  local prefix = "/etc/config"
  local run = function()
    sink("cat " .. prefix)
  end
  prefix = "/tmp"
  prefix = "/var/run"
  return run
end

-- The later write is on one side of a branch, so the register's value at the closure
-- is still reachable and belongs in the set alongside it.
local function a_write_on_one_branch(flag)
  local prefix = "/etc/config"
  local run = function()
    sink("cat " .. prefix)
  end
  if flag then
    prefix = "/tmp"
  end
  return run
end

-- A later write storing the result of a call. The member names where the value came
-- from rather than what it is, which is a complete answer about the set: the register
-- holds either the literal or whatever that call returned.
local function a_write_of_a_call_result()
  local prefix = "/etc/config"
  local run = function()
    sink("cat " .. prefix)
  end
  prefix = os.getenv("PREFIX")
  return run
end

-- A later write whose own value does not resolve, here because it is carried around a
-- loop. The set cannot be completed, so the reason has to stand rather than a partial
-- set being reported: a set reads as every possibility.
local function a_write_that_cannot_be_resolved(count)
  local prefix = "/etc/config"
  local run = function()
    sink("cat " .. prefix)
  end
  for index = 1, count do
    prefix = prefix .. index
  end
  return run
end

-- No write after the closure: the single reaching definition is already reported and
-- must not become a one-member alternatives set.
local function no_write_after_the_closure()
  local prefix = "/etc/config"
  local run = function()
    sink("cat " .. prefix)
  end
  return run
end

-- The capture is mutated through the closure itself, by assignment to the upvalue in a
-- child prototype. Those writes do not live in the parent and run at a time this
-- analysis does not model, so this case keeps the reason.
local function mutated_through_the_closure()
  local prefix = "/etc/config"
  local write = function()
    prefix = "/tmp"
  end
  local run = function()
    sink("cat " .. prefix)
  end
  return write, run
end

-- A write that happens before the closure is built, and a different one after. The
-- earlier write cannot reach the closure -- the register no longer holds it by the time
-- the upvalue is bound -- so it must not appear in the set. This separates "every write
-- to the register" from "every write that can reach this closure".
local function an_earlier_write_the_closure_cannot_see()
  local prefix = "/old"
  prefix = "/etc/config"
  local run = function()
    sink("cat " .. prefix)
  end
  prefix = "/tmp"
  return run
end

-- A later write storing the value the register already holds. Both definitions reach the
-- closure, but they are the same definition, so after deduplication the set has one
-- member and the capture resolves to that value. A one-member set would imply a choice
-- the program does not offer.
local function a_write_of_the_same_value()
  local prefix = "/etc/config"
  local run = function()
    sink("cat " .. prefix)
  end
  prefix = "/etc/config"
  return run
end

return {
  one_write_after_the_closure,
  two_writes_after_the_closure,
  a_write_on_one_branch,
  a_write_of_a_call_result,
  a_write_that_cannot_be_resolved,
  no_write_after_the_closure,
  mutated_through_the_closure,
  an_earlier_write_the_closure_cannot_see,
  a_write_of_the_same_value,
}
