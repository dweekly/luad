local sys = require("luci.sys")
local alias = sys.call
alias("alias")
sys:exec("method")

local direct = print
direct("direct")

local same
if arg then
  same = print
else
  same = print
end
same("same")

local conflict
if arg then
  conflict = print
else
  conflict = error
end
conflict("conflict")

local outer_module = sys
local function outer()
  local method = outer_module.fork_exec
  return function()
    method("nested")
  end
end
local nested = outer()
nested()

local mutable = print
local function mutated()
  mutable("mutated")
end
mutable = error
mutated()

local range_target = print
local first, last
first, range_target, last = unknown()
range_target("range")

local function forward(...)
  return print(...)
end
forward("open")

local function forward_dynamic(callee, ...)
  return callee(...)
end
forward_dynamic(print, "dynamic")
