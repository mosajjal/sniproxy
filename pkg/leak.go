package sniproxy

import (
	"context"
	"fmt"
	"io"
	"runtime/pprof"
	"time"

	"github.com/rcrowley/go-metrics"
	"github.com/rs/zerolog"
)

// GoroutineLeakProfile is the runtime/pprof profile that reports goroutines the
// runtime has proven can never become runnable again. A goroutine counts as
// leaked when it is blocked on a concurrency primitive (channel, sync.Mutex,
// sync.Cond, ...) that is unreachable from any goroutine which could still
// unblock it.
//
// sniproxy builds against Go 1.26, where this profile is opt-in: it only exists
// when the binary is built with GOEXPERIMENT=goroutineleakprofile. Without that
// the leak options degrade to a clear error rather than failing the build, so
// an ordinary `go install` still works. The profile becomes unconditional in Go
// 1.27.
//
// Detection is reachability based, so a goroutine blocked on a primitive that
// is still reachable through a global variable, or through the locals of a
// runnable goroutine, will not be reported even if nothing will ever signal it.
const GoroutineLeakProfile = "goroutineleak"

// GoroutineLeakExperiment is the GOEXPERIMENT value that compiles the profile
// into the binary on Go 1.26.
const GoroutineLeakExperiment = "goroutineleakprofile"

// GoroutineLeakProfileAvailable reports whether this binary was built with
// goroutine leak detection compiled in.
func GoroutineLeakProfileAvailable() bool {
	return pprof.Lookup(GoroutineLeakProfile) != nil
}

// WriteGoroutineLeakProfile writes the goroutine leak profile to w and returns
// the number of leaked goroutines found.
//
// Writing is what performs the detection: the runtime runs a dedicated GC cycle
// that marks unreachable-blocked goroutines as leaked. Reading the count on its
// own returns whatever the previous detection run produced, which is zero if
// there has never been one, so the count is only meaningful after a write.
//
// debug=0 emits the binary pprof format, debug=1 a human readable profile, and
// debug=2 dumps every goroutine stack in the format of an unrecovered panic.
//
// This forces a full GC and stops the world briefly, which is why sniproxy only
// ever calls it on demand rather than on a hot path.
func WriteGoroutineLeakProfile(w io.Writer, debug int) (int, error) {
	p := pprof.Lookup(GoroutineLeakProfile)
	if p == nil {
		return 0, fmt.Errorf("%q profile unavailable: rebuild with GOEXPERIMENT=%s (or with Go 1.27+, where it is always on)", GoroutineLeakProfile, GoroutineLeakExperiment)
	}
	if err := p.WriteTo(w, debug); err != nil {
		return 0, fmt.Errorf("failed to write %q profile: %w", GoroutineLeakProfile, err)
	}
	return p.Count(), nil
}

// CountGoroutineLeaks runs leak detection and reports how many goroutines are
// leaked, discarding the profile itself.
func CountGoroutineLeaks() (int, error) {
	return WriteGoroutineLeakProfile(io.Discard, 0)
}

// WatchGoroutineLeaks runs leak detection every interval until ctx is done,
// publishing the result to gauge and logging a warning whenever the count is
// above zero.
//
// Every check forces a full GC, so this is off by default and the interval
// should stay coarse (minutes, not seconds) on a busy proxy.
func WatchGoroutineLeaks(ctx context.Context, interval time.Duration, gauge metrics.Gauge, logger zerolog.Logger) {
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			n, err := CountGoroutineLeaks()
			if err != nil {
				logger.Error().Err(err).Msg("goroutine leak check failed, stopping the watcher")
				return
			}
			if gauge != nil {
				gauge.Update(int64(n))
			}
			if n > 0 {
				logger.Warn().Int("leaked", n).Msgf("leaked goroutines detected; fetch /debug/pprof/%s for stacks", GoroutineLeakProfile)
			} else {
				logger.Debug().Msg("goroutine leak check found no leaks")
			}
		}
	}
}
