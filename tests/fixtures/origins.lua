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

  local vararg = ...
  sink(vararg)
  sink(producer(parameter))

  local table_value = { parameter }
  local table_alias = table_value
  table_value[1] = "changed"
  sink(table_alias)
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
