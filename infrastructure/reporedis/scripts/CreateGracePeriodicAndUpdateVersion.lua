
local sess_key = KEYS[1]
local grace_periodic_key = KEYS[2]
local new_version = ARGV[1]
local access_token = ARGV[2]
local refresh_token = ARGV[3]
local time_now = tonumber(ARGV[4])
local lifetime_access = tonumber(ARGV[5])

local field_version = "version"
local field_access = "access"
local field_refresh = "refresh"
local field_last_update = "last_update"

local function to_hash_map(raw_data)
    local hash_map = {}
    if not raw_data then return hash_map end
    
    for i = 1, #raw_data, 2 do
        local key = raw_data[i]
        local value = raw_data[i + 1]
        hash_map[key] = value
    end
    
    return hash_map
end

if not time_now or not lifetime_access then
    return redis.error_reply("bad args")
end

local cur_ver = redis.call("HGET", sess_key, field_version)
local last_update = redis.call("HGET", sess_key, field_last_update)

if not cur_ver or not last_update then
    return redis.error_reply("session not found")
end

local diff = time_now - last_update

if diff <= lifetime_access then
    return redis.error_reply("suspicious refresh rate")
end

local grace_periodic_is_exist = redis.call("EXISTS", grace_periodic_key)

if grace_periodic_is_exist == 1 then

    local data = redis.call("HGETALL", grace_periodic_key)

    local hash_data = to_hash_map(data)
    
    if hash_data[field_version] == new_version then
        return redis.error_reply("grace periodic alredy exist")        
    else
        return redis.error_reply("grace periodic version mismatch")        
    end
end

redis.call("HSET", sess_key, field_version, new_version)
redis.call("HSET", sess_key, field_last_update, time_now)

redis.call("HSET", grace_periodic_key, field_version, new_version)
redis.call("HSET", grace_periodic_key, field_access, access_token)
redis.call("HSET", grace_periodic_key, field_refresh, refresh_token)