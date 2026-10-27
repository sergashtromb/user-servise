
local sess_key = KEYS[1]
local grace_periodic_key = KEYS[2]
local requested_version = ARGV[1]

local field_version = "version"
local field_access = "access"
local field_refresh = "refresh"
local field_last_update = "last_update"

local cur_ver = redis.call("HGET", sess_key, field_version)
local last_update = redis.call("HGET", sess_key, field_last_update)

if not cur_ver or not last_update then
    return redis.error_reply("session not found")
end

local grace_exists = redis.call("EXISTS", grace_periodic_key)

if grace_exists == 0 then
    return redis.error_reply("grace periodic not exists")
end

local data = redis.call("HGETALL", grace_periodic_key)

if #data == 0 then
    return redis.error_reply("grace periodic not exists")
end

local grace_version = redis.call("HGET", grace_periodic_key, field_version)

if not grace_version or grace_version ~= requested_version then
    return redis.error_reply("grace periodic version mismatch")
end

local access = redis.call("HGET", grace_periodic_key, field_access)
local refresh = redis.call("HGET", grace_periodic_key, field_refresh)

if not access or not refresh then
    return redis.error_reply("bad data")
end

return {access, refresh}
