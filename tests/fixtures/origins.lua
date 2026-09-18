local sink = function(...)
  return ...
end

local function producer(value)
  return value, "second"
end

local root_capture = "root"

local function make_outer(parent_parameter)
  local local_capture = parent_parameter
  return function(child_parameter)
    return function(grandchild_parameter)
      sink(root_capture, local_capture, child_parameter, grandchild_parameter)
    end
  end
end

local function matrix(parameter, number, ...)
  local literal_string = "literal"
  local literal_number = 42
  local literal_boolean = true
  local literal_nil = nil
  sink(literal_string, literal_number, literal_boolean, literal_nil, parameter)

  local moved = parameter
  local concatenated = "prefix:" .. moved .. ":suffix"
  sink(concatenated)

  local formatted = "value=%s" % { parameter }
  sink(formatted)

  sink(-number, not parameter, #parameter)
  sink(
    number + 1,
    number - 2,
    number * 3,
    number / 4,
    number % 5,
    number ^ 6
  )

  sink(string.byte, math["floor"], math[parameter])

  local first, second = producer(parameter)
  sink(first, second)

  local same
  if parameter then
    same = "same"
  else
    same = "same"
  end
  sink(same)

  local conflict
  if parameter then
    conflict = "left"
  else
    conflict = "right"
  end
  sink(conflict)

  local alt_param
  if parameter then
    alt_param = "literal_val"
  else
    alt_param = parameter
  end
  sink(alt_param)

  local loop_val = "init"
  for i = 1, 3 do
    loop_val = "iter"
  end
  sink(loop_val)

  local unresolved_alt
  if parameter then
    unresolved_alt = "defined"
  else
    unresolved_alt = math[parameter]
  end
  sink(unresolved_alt)

  local overflow_alt
  if parameter == 1 then
    overflow_alt = "o1"
  elseif parameter == 2 then
    overflow_alt = "o2"
  elseif parameter == 3 then
    overflow_alt = "o3"
  elseif parameter == 4 then
    overflow_alt = "o4"
  elseif parameter == 5 then
    overflow_alt = "o5"
  elseif parameter == 6 then
    overflow_alt = "o6"
  elseif parameter == 7 then
    overflow_alt = "o7"
  elseif parameter == 8 then
    overflow_alt = "o8"
  else
    overflow_alt = "o9"
  end
  sink(overflow_alt)

  local vararg = ...
  sink(vararg)
  sink(producer(parameter))

  local table_value = { parameter }
  local table_alias = table_value
  table_value[1] = "changed"
  sink(table_alias)

  local complete_table = {}
  complete_table.a = "x"
  complete_table.b = parameter
  sink(complete_table)

  local dynamic_table = {}
  dynamic_table.a = "x"
  dynamic_table[parameter] = 123
  sink(dynamic_table)

  local escaped_table = {}
  escaped_table.a = "x"
  producer(escaped_table)
  escaped_table.b = "y"
  sink(escaped_table)

  local aliased_table = {}
  local alias_ref = aliased_table
  aliased_table.a = "x"
  alias_ref.b = "y"
  sink(alias_ref)

  local overwrite_table = {}
  overwrite_table.a = "first"
  overwrite_table.a = "second"
  sink(overwrite_table)

  local conflict_table = {}
  if parameter then
    conflict_table.a = 1
  else
    conflict_table.a = 2
  end
  sink(conflict_table)

  sink(function() end)
end

local function deep_expression(parameter)
  local value = parameter
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  value = #value
  sink(value)
end

local function unreachable_call()
  do
    return
  end
  sink("unreachable")
end

matrix("parameter", 7, "vararg")
make_outer("capture")("child")("grandchild")
deep_expression("deep")
unreachable_call()
