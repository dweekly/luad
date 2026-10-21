-- A table access whose key is a register rather than a constant operand. The key register
-- may still hold a bounded set of reaching definitions, in which case the field is nameable;
-- `dynamic-key` belongs to the keys that are genuinely not determinable.

local function literal_key(params)
  local k = "dir"
  sink(params[k])
end
local function branch_key(params, flag)
  local k
  if flag then k = "dir" else k = "path" end
  sink(params[k])
end
local function truly_dynamic(params)
  sink(params[compute()])
end
local function loop_key(params, n)
  local out
  for i = 1, n do out = params[i] end
  sink(out)
end
