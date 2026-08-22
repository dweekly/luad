local t = { 1, 2, 3, 4, 5, name = "luad", active = true }
t[10] = "ten"
t.nested = { a = 1, b = 2 }

local meta = {
    __add = function(a, b)
        return a[1] + b[1]
    end
}
setmetatable(t, meta)

return t
