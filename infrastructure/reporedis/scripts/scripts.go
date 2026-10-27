package scripts

import (
	"embed"
	"fmt"

	"github.com/redis/go-redis/v9"
)

//go:embed *.lua
var luaScripts embed.FS

var (
	CreateGracePeriodicAndUpdateVersion = redis.NewScript(loadScript("CreateGracePeriodicAndUpdateVersion.lua"))
	GetFromGracePeriodic                = redis.NewScript(loadScript("GetFromGracePeriodic.lua"))
)

func loadScript(name string) string {
	data, err := luaScripts.ReadFile(name)
	if err != nil {
		panic(fmt.Sprintf("Failed load lua script redis - %v", name))
	}

	return string(data)
}
