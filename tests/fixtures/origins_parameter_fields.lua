-- The input contract of a prototype that takes a table: which constant keys it reads out of,
-- and writes back to, each parameter. The base is resolved to a parameter by the dataflow,
-- so a key read off something that merely sits in the parameter's register does not count.

local function reads_three_keys(params)
  if not params.name or not params.type then
    return nil, "invalid params"
  end
  return params.enable
end

local function nested_and_written(params)
  params.result = params.opts.mode
  return params.result
end

local function base_is_not_a_parameter(params)
  local other = { mode = "0755" }
  return other.mode, os.time()
end

local function parameter_register_reassigned(params)
  params = { mode = "0755" }
  return params.mode
end

local function method_call_on_a_parameter(params)
  return params:render()
end

local function written_through_a_register_key(params, key)
  params[key] = "0755"
end

local function written_through_a_constant_key_with_a_constant_value(params)
  params.mode = "0755"
end

return {
  reads_three_keys,
  nested_and_written,
  base_is_not_a_parameter,
  parameter_register_reassigned,
  method_call_on_a_parameter,
  written_through_a_register_key,
  written_through_a_constant_key_with_a_constant_value,
}
