local integer_zero = 0
local integer_min = 0x80000000
local integer_max = 2147483647
local float_fraction = 1.5
local float_integral = 1.0
local short_text = "openwrt-lnum32"
local long_text = "abcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmnopqrstuvwxyzabcdefghijklmn"

local captured_root = 7
local function outer(delta)
    local captured_local = 11
    return function(x)
        return function(y)
            return captured_root + captured_local + delta + x + y
        end
    end
end

local values = { key = 3 }
values[short_text] = values.key + integer_max

if float_fraction > float_integral then
    values.branch = math.floor(float_fraction)
else
    values.branch = integer_zero
end

for i = 1, 3 do
    values[i] = i + integer_min
end

for key, value in pairs(values) do
    if key == "never" then
        values[key] = value
    end
end

return integer_zero, integer_min, integer_max, float_fraction, float_integral,
    short_text, long_text, outer, values
