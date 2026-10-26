package reporedis

const (
	RepoName = "Redis"
)

const (
	FieldId         = "id"
	FieldUserName   = "user_name"
	FieldEmail      = "email"
	FieldPhone      = "phone"
	FieldCreatedAt  = "created_at"
	FieldIsDeleted  = "is_deleted"
	FieldUserId     = "user_id"
	FieldDeviceId   = "device_id"
	FieldIp         = "ip"
	FieldAgent      = "agent"
	FieldExpAt      = "expiration_at"
	FieldVersion    = "version"
	FieldLastUpdate = "last_update"
)

// err lua conts
const (
	ErrLuaBadArgs               = "bad args"
	ErrLuaSessionNotFound       = "session not found"
	ErrLuaSuspiciousRefreshRate = "suspicious refresh rate"
	ErrLuaBadVersion            = "bad version"
)
