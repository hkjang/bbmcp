// Package httpx holds small HTTP helpers shared by the API handlers.
package httpx

import (
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// JSON writes a JSON response.
func JSON(w http.ResponseWriter, status int, body any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	if body != nil {
		_ = json.NewEncoder(w).Encode(body)
	}
}

// ErrorBody is the shape of every API error.
type ErrorBody struct {
	Error   string `json:"error"`
	Code    string `json:"code,omitempty"`
	Details string `json:"details,omitempty"`
}

// Fail writes a JSON error.
func Fail(w http.ResponseWriter, status int, message string) {
	JSON(w, status, ErrorBody{Error: message})
}

// FailCode writes a JSON error with a machine-readable code.
func FailCode(w http.ResponseWriter, status int, code, message string) {
	JSON(w, status, ErrorBody{Error: message, Code: code})
}

// Decode reads a JSON body into out, rejecting unknown fields.
func Decode(r *http.Request, out any) error {
	dec := json.NewDecoder(http.MaxBytesReader(nil, r.Body, 4<<20))
	return dec.Decode(out)
}

// ClientIP extracts the caller address, honouring proxy headers when trusted.
func ClientIP(r *http.Request, trustProxy bool) string {
	if trustProxy {
		if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
			parts := strings.Split(xff, ",")
			return strings.TrimSpace(parts[0])
		}
		if xr := r.Header.Get("X-Real-IP"); xr != "" {
			return strings.TrimSpace(xr)
		}
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

// IPAllowed checks an address against a CIDR/exact allowlist. An empty list
// allows everything, which is the default for an isolated network.
func IPAllowed(ip string, allowlist []string) bool {
	if len(allowlist) == 0 {
		return true
	}
	addr := net.ParseIP(ip)
	for _, entry := range allowlist {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}
		if entry == ip {
			return true
		}
		if _, network, err := net.ParseCIDR(entry); err == nil && addr != nil && network.Contains(addr) {
			return true
		}
	}
	return false
}

// RateLimiter is a per-key token bucket.
type RateLimiter struct {
	mu      sync.Mutex
	buckets map[string]*bucket
}

type bucket struct {
	tokens float64
	last   time.Time
}

// NewRateLimiter builds a limiter.
func NewRateLimiter() *RateLimiter {
	rl := &RateLimiter{buckets: map[string]*bucket{}}
	go rl.sweep()
	return rl
}

func (rl *RateLimiter) sweep() {
	t := time.NewTicker(5 * time.Minute)
	for range t.C {
		rl.mu.Lock()
		for k, b := range rl.buckets {
			if time.Since(b.last) > 10*time.Minute {
				delete(rl.buckets, k)
			}
		}
		rl.mu.Unlock()
	}
}

// Allow consumes a token for key, refilling at perMinute with the given burst.
func (rl *RateLimiter) Allow(key string, perMinute, burst int) bool {
	if perMinute <= 0 {
		return true
	}
	if burst <= 0 {
		burst = perMinute
	}
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	b, ok := rl.buckets[key]
	if !ok {
		rl.buckets[key] = &bucket{tokens: float64(burst) - 1, last: now}
		return true
	}
	refill := now.Sub(b.last).Minutes() * float64(perMinute)
	b.tokens = min(float64(burst), b.tokens+refill)
	b.last = now
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

func min(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}

// NoCache marks a response as uncacheable, used for API and HTML shells.
func NoCache(w http.ResponseWriter) {
	w.Header().Set("Cache-Control", "no-store, no-cache, must-revalidate")
	w.Header().Set("Pragma", "no-cache")
}

// NoCacheMiddleware marks every response in a route group as uncacheable.
func NoCacheMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		NoCache(w)
		next.ServeHTTP(w, r)
	})
}
