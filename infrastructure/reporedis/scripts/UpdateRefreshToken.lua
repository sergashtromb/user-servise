
-- keys:
-- session:{hexUserId}:refresh:<hashOldKey>
-- session:{hexUserId}:user:<hashOldKey>
-- session:{hexUserId}:refresh:<hashNewKey>
-- session:{hexUserId}:user:<hashNewKey>

-- arguments:
-- ttl
-- <hashNewKey>

local old_key = KEYS[1]
local old_key_with_user = KEYS[2] 
local new_key = KEYS[3] 
local new_key_with_user = KEYS[4] 
local ttl = tonumber(ARGV[1])
local new_key_hash = ARGV[2]

if not ttl or ttl <= 0 then
    return redis.error_reply("invalid ttl")
end

if redis.call('EXISTS', old_key) == 0 then
    return 0
end

redis.call('RENAME', old_key, new_key)
redis.call('SET', new_key_with_user, new_key_hash, 'EX', ttl)
redis.call('DEL', old_key_with_user)

redis.call('EXPIRE', new_key, ttl)

return 1



