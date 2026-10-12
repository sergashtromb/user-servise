package scripts

import (
	"embed"

	"github.com/redis/go-redis/v9"
)

//go:embed *.lua
var luaScripts embed.FS

var (
	UpdateRefreshToken = redis.NewScript(loadScript("UpdateRefreshToken.lua"))
)

func loadScript(name string) string {
	data, err := luaScripts.ReadFile(name)
	if err != nil {
		panic("Failed load lua script redis")
	}

	return string(data)
}
