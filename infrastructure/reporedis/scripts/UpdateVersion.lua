
local sess_key = KEYS[1]
local time_now = tonumber(ARGV[1])
local lifetime_access = tonumber(ARGV[2])

local function split(inputstr, sep)
    if sep == nil then
        sep = "%s"
    end
    local t = {}

    for str in string.gmatch(inputstr, "([^" .. sep .. "]+)") do
        table.insert(t, str)
    end
    return t
end

if not time_now or not lifetime_access then
    return redis.error_reply("bad args")
end

local cur_ver = redis.call("HGET", sess_key, "version")
local last_update = redis.call("HGET", sess_key, "last_update")

if not cur_ver or not last_update then
    return redis.error_reply("session not found")
end


local diff = time_now - last_update

if diff <= lifetime_access then
    return redis.error_reply("suspicious refresh rate")
end

-- version have format jwt-vernumber

local comp_ver = split(cur_ver, "-")
if #comp_ver < 2 then
    return redis.error_reply("bad version")
end

local num = tonumber(comp_ver[2])
num = num + 1

local new_version = comp_ver[1] .. "-" .. tostring(num)

redis.call("HSET", sess_key, "version", new_version)
redis.call("HSET", sess_key, "last_update", time_now)

return new_version