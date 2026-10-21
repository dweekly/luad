-- Once something outside this prototype holds a table, it may write any key, so a field
-- written before that point is not a fact at a later call site. A field written after it
-- still is, and a table whose every field predates the escape has nothing left to report.

local function every_field_predates_the_escape()
  local t = { dir = "/etc" }
  mutate(t)
  sink(t)
end

local function a_field_written_after_the_escape_survives()
  local t = { dir = "/etc" }
  mutate(t)
  t.mode = "0755"
  sink(t)
end

local function every_field_postdates_the_escape()
  local t = {}
  mutate(t)
  t.mode = "0755"
  sink(t)
end

local function a_call_that_never_receives_it_changes_nothing()
  local t = { dir = "/etc" }
  log("starting")
  sink(t)
end

local function reaching_a_global_is_also_an_escape()
  local t = { dir = "/etc" }
  exported = t
  sink(t)
end

return {
  every_field_predates_the_escape,
  a_field_written_after_the_escape_survives,
  every_field_postdates_the_escape,
  a_call_that_never_receives_it_changes_nothing,
  reaching_a_global_is_also_an_escape,
}
