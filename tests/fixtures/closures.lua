local function make_counter(start)
    local count = start or 0
    return function(step)
        count = count + (step or 1)
        local function inner()
            return count * 2
        end
        return count, inner
    end
end

local c = make_counter(10)
local val, inner_fn = c(5)
return val, inner_fn()
