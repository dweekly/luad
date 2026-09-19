-- Loop-carried values make the origin lattice grow without bound.
--
-- At the loop head the merge of `index` yields Alternatives[0, ADD(0, 1)]. The transfer
-- of `index = index + 1` then yields ADD(Alternatives[..], 1), which the next merge adds
-- as a further option, one nesting level per iteration. Nothing in the expression bounds
-- collapses that, so without widening the worklist never reaches a fixpoint and stops
-- only by exhausting its step budget, which reports every call in the prototype as
-- `analysis-limit` including the ones that converged immediately.
--
-- The argument to the final sink is deliberately ordinary: two literals and a field read
-- off a parameter, none of it loop-carried. It must resolve.

local function sink(...) end

local function loop_counter(params)
  local index = 0
  local total = 0
  while index < 10 do
    index = index + 1
    total = total + index
  end
  sink(total)
  sink("mkdir -p " .. "/tmp/widen/" .. params.opcode)
  return total
end

loop_counter({ opcode = "x" })
