local function direct_target(value)
  return value
end

local direct_alias = direct_target
direct_alias("direct")

global_first = direct_target
global_first("first")

local function second_target(value)
  return value
end

global_second = second_target
global_second("second")

local same_target
if arg then
  same_target = direct_target
else
  same_target = direct_target
end
same_target("same")

local conflicting_target
if arg then
  conflicting_target = direct_target
else
  conflicting_target = second_target
end
conflicting_target("conflict")

collision = direct_target
collision = second_target
collision("collision")

not_a_closure = 42
not_a_closure("non-closure")

print("external")

local function outer()
  local captured = direct_target
  return function()
    return function(value)
      return captured(value)
    end
  end
end

local middle = outer()
local inner = middle()
inner("capture")

local mutable = direct_target
local function mutable_caller(value)
  return mutable(value)
end
mutable = second_target
mutable_caller("mutable")
