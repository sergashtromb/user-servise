package limiter

import (
	"context"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

// TODO add shell for rate.Limiter
// add field lastUse - time.Time
// add method for check how much time limiter unsual

type Shard struct {
	rm   sync.RWMutex
	data map[string]*rate.Limiter
}

type ShardLimiter struct {
	rm          sync.Mutex
	shards      []Shard
	qntyShards  int
	cap         int
	speedFill   float64
	timeForDel  time.Duration
	timeDontUse time.Duration
}

func NewShardLimiter(qs, cap int, speedFill float64, tfd, tdu time.Duration) *ShardLimiter {

	sl := ShardLimiter{
		shards:      make([]Shard, qs),
		qntyShards:  qs,
		cap:         cap,
		speedFill:   speedFill,
		timeForDel:  tfd,
		timeDontUse: tdu,
	}

	for val := range qs {
		sl.shards[val].data = make(map[string]*rate.Limiter)
	}

	return &sl
}

func (sl *ShardLimiter) Allow(ip string) bool {

	idx := sl.getShardIndexFromIp(ip)
	shard := &sl.shards[idx]

	shard.rm.Lock()
	defer shard.rm.RUnlock()

	lim, ok := shard.data[ip]
	if !ok {
		lim := rate.NewLimiter(rate.Limit(sl.speedFill), sl.cap)
		shard.data[ip] = lim
	}

	return lim.Allow()

}

func (sl *ShardLimiter) getShardIndexFromIp(ip string) int {
	net_ip := net.ParseIP(ip).To4()
	if net_ip == nil {
		return 0
	}

	index := uint32(net_ip[0])<<24 | uint32(net_ip[1])<<16 | uint32(net_ip[2])<<8 | uint32(net_ip[3])

	return int(index % uint32(sl.cap))
}

func (sh *Shard) DelLimiter(ip string) {
	sh.rm.Lock()
	defer sh.rm.Unlock()

	delete(sh.data, ip)
}

func (sl *ShardLimiter) DeleteUnuse(ctx context.Context) {

	ticker := time.NewTicker(sl.timeForDel)
	defer ticker.Stop()

	for {

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:

			now := time.Now()

			for i := range sl.qntyShards {

				shard := &sl.shards[i]
				ipForDel := make([]string, 0, len(shard.data))

				shard.rm.RLock()

				shard.rm.Unlock()

			}

		}

	}

}
