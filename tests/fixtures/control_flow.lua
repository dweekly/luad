local x = 10
if x > 5 then
    x = x + 1
else
    x = x - 1
end

local sum = 0
for i = 1, 10 do
    sum = sum + i
end

while sum > 0 do
    sum = sum - 5
    if sum == 15 then
        break
    end
end

repeat
    x = x * 2
until x > 100

return x, sum
