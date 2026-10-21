-- An open argument window is top-dependent only from the point the top-producing instruction
-- writes. Arguments at fixed registers before that point are ordinary determinable arguments,
-- and for a shell-shaped call the first argument is usually the one a reader came for.

local function prefix_then_open(params)
  sink("rm -rf " .. params.dir, "flag", helper())
end

local function open_from_the_first_argument(params)
  sink(unpack(params))
end

local function prefix_holds_an_unresolved_argument(params)
  sink(params[compute()], "literal", helper())
end

local function tail_call_with_a_prefix(params)
  return sink("cat " .. params.path, helper())
end

return {
  prefix_then_open,
  open_from_the_first_argument,
  prefix_holds_an_unresolved_argument,
  tail_call_with_a_prefix,
}
