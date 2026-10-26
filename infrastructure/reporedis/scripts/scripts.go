package scripts

import (
	"embed"
	"fmt"

	"github.com/redis/go-redis/v9"
)

//go:embed *.lua
var luaScripts embed.FS

var (
	// TEST write test for check invalid ttl, should return error
	// FORDEL
	UpdateRefreshToken = redis.NewScript(loadScript("UpdateRefreshToken.lua"))
	UpdateVersion      = redis.NewScript(loadScript("UpdateVersion.lua"))
)

func loadScript(name string) string {
	data, err := luaScripts.ReadFile(name)
	if err != nil {
		panic(fmt.Sprintf("Failed load lua script redis - %v", name))
	}

	return string(data)
}
