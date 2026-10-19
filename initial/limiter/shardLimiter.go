package limiter

import (
	"context"
	"net"
	"sync"
	"time"

	"golang.org/x/time/rate"
)

type ShardRateLimiter interface {
	Allow(ip string) bool
}

type ShellLimiter struct {
	rate.Limiter
	mu      sync.Mutex
	lastUse time.Time
}

func NewShellLimiter(spf float64, cap int) *ShellLimiter {
	return &ShellLimiter{
		Limiter: *rate.NewLimiter(rate.Limit(spf), cap),
		lastUse: time.Now(),
	}
}

func (sl *ShellLimiter) Allow() bool {
	sl.mu.Lock()
	sl.lastUse = time.Now()
	sl.mu.Unlock()

	return sl.Limiter.Allow()
}

func (sl *ShellLimiter) IsUsed(start time.Time) bool {
	return sl.lastUse.After(start)
}

type Shard struct {
	rm   sync.RWMutex
	data map[string]*ShellLimiter
}

func (sh *Shard) DelLimiter(ip string) {
	sh.rm.Lock()
	defer sh.rm.Unlock()

	delete(sh.data, ip)
}

func (sh *Shard) DelIfUnuse(ip string, timeUnuse time.Time) {

	sh.rm.Lock()
	defer sh.rm.Unlock()

	lim, ok := sh.data[ip]
	if !ok {
		return
	}

	if !lim.IsUsed(timeUnuse) {
		delete(sh.data, ip)
	}
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
		sl.shards[val].data = make(map[string]*ShellLimiter)
	}

	return &sl
}

func (sl *ShardLimiter) Allow(ip string) bool {

	idx := sl.getShardIndexFromIp(ip)
	shard := &sl.shards[idx]

	shard.rm.Lock()
	defer shard.rm.Unlock()

	lim, ok := shard.data[ip]
	if !ok {
		lim := NewShellLimiter(sl.speedFill, sl.cap)
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

func (sl *ShardLimiter) DeleteUnuse(ctx context.Context) {

	ticker := time.NewTicker(sl.timeForDel)
	defer ticker.Stop()

	for {

		select {
		case <-ctx.Done():
			return
		case <-ticker.C:

			now := time.Now().Add(-1 * sl.timeDontUse)

			for i := range sl.qntyShards {

				shard := &sl.shards[i]
				ipForDel := make([]string, 0, len(shard.data))

				shard.rm.RLock()
				for key, val := range shard.data {
					if !val.IsUsed(now) {
						ipForDel = append(ipForDel, key)
					}
				}
				shard.rm.RUnlock()

				for _, val := range ipForDel {
					shard.DelIfUnuse(val, now)
				}

			}

		}

	}

}

type MockShardLimiter struct{}

func (msl *MockShardLimiter) Allow(ip string) bool {
	return true
}

func GetMockShardLimiter() ShardRateLimiter {
	m := MockShardLimiter{}
	ref := &m
	return ref
}
