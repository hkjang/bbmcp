package api

import (
	"sync"
	"time"
	"unicode/utf8"
)

// The discovery trace answers the question an operator cannot answer from the
// agent's error alone: did the agent actually ask this gateway? A client that
// registers here shows up as 401 → protected resource metadata →
// authorization server metadata → registration. One that still goes to
// Keycloak (an old process answered, the registration switch was off, or the
// client reused a cached or pinned authorization server) shows the 401 and
// nothing after it, here.
//
// It is kept in memory per process, since boot, which after an upgrade is the
// window that matters. Each kind of event has its own small ring so busy MCP
// traffic cannot push the discovery events out, every stored string is
// bounded, and inserts are rate limited because all of these endpoints are
// unauthenticated.

// traceEvent is one OAuth discovery step as this process saw it.
type traceEvent struct {
	At     time.Time `json:"at"`
	Kind   string    `json:"kind"`
	Method string    `json:"method"`
	Path   string    `json:"path"`
	Status int       `json:"status"`
	IP     string    `json:"ip"`
	Agent  string    `json:"userAgent"`
	Detail string    `json:"detail,omitempty"`
}

const (
	traceChallenge    = "challenge"
	traceResourceMeta = "resource-metadata"
	traceServerMeta   = "server-metadata"
	traceRegister     = "register"
	traceUnknown      = "unknown-well-known"
)

var traceKinds = []string{traceChallenge, traceResourceMeta, traceServerMeta, traceRegister, traceUnknown}

const (
	traceRingSize  = 100
	tracePerSecond = 20
)

type discoveryTrace struct {
	mu    sync.Mutex
	rings map[string][]traceEvent
	// Each kind has its own one-second budget, so a flood of 401s or unknown
	// paths cannot drop the registration steps an operator is looking for.
	windows map[string]traceWindow
}

type traceWindow struct {
	start time.Time
	count int
}

func newDiscoveryTrace() *discoveryTrace {
	return &discoveryTrace{rings: map[string][]traceEvent{}, windows: map[string]traceWindow{}}
}

func (t *discoveryTrace) record(e traceEvent) {
	if t == nil {
		return
	}
	e.Path = clip(e.Path, 160)
	e.IP = clip(e.IP, 64)
	e.Agent = clip(e.Agent, 160)
	e.Detail = clip(e.Detail, 240)
	e.Method = clip(e.Method, 10)
	if e.At.IsZero() {
		e.At = time.Now()
	}

	t.mu.Lock()
	defer t.mu.Unlock()
	w := t.windows[e.Kind]
	if now := time.Now(); now.Sub(w.start) >= time.Second {
		w = traceWindow{start: now}
	}
	if w.count >= tracePerSecond {
		return
	}
	w.count++
	t.windows[e.Kind] = w
	ring := append(t.rings[e.Kind], e)
	if len(ring) > traceRingSize {
		ring = ring[len(ring)-traceRingSize:]
	}
	t.rings[e.Kind] = ring
}

// snapshot returns every kept event, newest first.
func (t *discoveryTrace) snapshot() []traceEvent {
	t.mu.Lock()
	defer t.mu.Unlock()
	out := []traceEvent{}
	for _, kind := range traceKinds {
		out = append(out, t.rings[kind]...)
	}
	// Small n: insertion sort by time, newest first.
	for i := 1; i < len(out); i++ {
		for j := i; j > 0 && out[j].At.After(out[j-1].At); j-- {
			out[j], out[j-1] = out[j-1], out[j]
		}
	}
	return out
}

// clip shortens a caller-supplied string without splitting a character.
func clip(v string, n int) string {
	if len(v) <= n {
		return v
	}
	cut := n
	for cut > 0 && !utf8.RuneStart(v[cut]) {
		cut--
	}
	return v[:cut] + "…"
}
