package permission

import (
	"fmt"
	"sync"
	"testing"
	"time"
)

// newTestResolver builds a resolver with no settings store or provider. Only
// the cache helpers (store_/cached/Reset) are exercised here, and none of them
// dereference store or provider.
func newTestResolver() *Resolver {
	return NewResolver(nil, nil)
}

func testDecision(repo string) Decision {
	return decide("u", "P", repo, Read, "test", "")
}

// 수용 기준 1) 캐시는 키 카디널리티와 무관하게 상한을 가진다.
func TestCacheStaysWithinMaxEntries(t *testing.T) {
	r := newTestResolver()
	total := maxCacheEntries + 100
	for i := 0; i < total; i++ {
		key := fmt.Sprintf("repo|u|P|r%d", i)
		r.store_(key, testDecision(fmt.Sprintf("r%d", i)), time.Minute)
	}
	if got := len(r.cache); got > maxCacheEntries {
		t.Fatalf("len(cache) = %d, want <= %d (삽입 %d건)", got, maxCacheEntries, total)
	}
	if len(r.cache) == 0 {
		t.Fatalf("len(cache) = 0, 회수가 캐시를 통째로 비웠습니다")
	}
}

// 수용 기준 2-a) ttl <= 0 이면 캐시하지 않는다.
func TestZeroOrNegativeTTLIsNotCached(t *testing.T) {
	r := newTestResolver()
	r.store_("repo|u|P|zero", testDecision("zero"), 0)
	r.store_("repo|u|P|neg", testDecision("neg"), -time.Second)
	if len(r.cache) != 0 {
		t.Fatalf("len(cache) = %d, want 0", len(r.cache))
	}
	if _, ok := r.cached("repo|u|P|zero"); ok {
		t.Fatalf("ttl 0 인 키가 캐시 적중했습니다")
	}
	if _, ok := r.cached("repo|u|P|neg"); ok {
		t.Fatalf("ttl 음수인 키가 캐시 적중했습니다")
	}
}

// 수용 기준 2-b) 만료된 키는 cached() 가 false 를 돌려주고 맵에서 사라진다.
func TestExpiredEntryMissesAndIsDeleted(t *testing.T) {
	r := newTestResolver()
	key := "repo|u|P|short"
	r.store_(key, testDecision("short"), 20*time.Millisecond)
	if _, ok := r.cached(key); !ok {
		t.Fatalf("만료 전 캐시 적중에 실패했습니다")
	}
	time.Sleep(40 * time.Millisecond)
	if _, ok := r.cached(key); ok {
		t.Fatalf("만료된 키가 캐시 적중했습니다")
	}
	if _, ok := r.cache[key]; ok {
		t.Fatalf("만료된 키가 조회 후에도 맵에 남아 있습니다")
	}
}

// 수용 기준 2-c) 회수는 어떤 항목의 만료 시각도 늘리지 않고, 만료된 결정을
// 되살리지도 않는다 — 회수의 유일한 결과는 "다음 호출에서 다시 조회" 다.
func TestEvictionNeitherExtendsExpiryNorRevivesExpired(t *testing.T) {
	r := newTestResolver()

	expired := "repo|u|P|expired"
	r.store_(expired, testDecision("expired"), 20*time.Millisecond)
	time.Sleep(40 * time.Millisecond)

	// 서로 다른 ttl 로 넣어 두고 삽입 직후의 만료 시각을 기록한다.
	want := map[string]time.Time{}
	for i := 0; i < maxCacheEntries+100; i++ {
		key := fmt.Sprintf("repo|u|P|r%d", i)
		r.store_(key, testDecision(fmt.Sprintf("r%d", i)), time.Duration(10+i%7)*time.Minute)
		if e, ok := r.cache[key]; ok {
			want[key] = e.exp
		}
	}

	for key, e := range r.cache {
		if exp, ok := want[key]; ok && !e.exp.Equal(exp) {
			t.Fatalf("%s 의 만료 시각이 %v → %v 로 바뀌었습니다", key, exp, e.exp)
		}
	}
	if _, ok := r.cached(expired); ok {
		t.Fatalf("만료된 결정이 회수 과정에서 되살아났습니다")
	}
}

// 수용 기준 3) Reset() 후 맵이 비고 이전 키는 모두 미적중이다.
func TestResetClearsCache(t *testing.T) {
	r := newTestResolver()
	keys := []string{"repo|u|P|a", "repo|u|P|b", "proj|u|P"}
	for _, k := range keys {
		r.store_(k, testDecision(k), time.Minute)
	}
	r.Reset()
	if len(r.cache) != 0 {
		t.Fatalf("Reset 후 len(cache) = %d, want 0", len(r.cache))
	}
	for _, k := range keys {
		if _, ok := r.cached(k); ok {
			t.Fatalf("Reset 후 %s 가 캐시 적중했습니다", k)
		}
	}
}

// 회수 로직이 기존 뮤텍스 아래에서만 돌아야 하므로 -race 로 함께 돌린다.
func TestConcurrentStoreAndLookupStayBounded(t *testing.T) {
	r := newTestResolver()
	var wg sync.WaitGroup
	for w := 0; w < 4; w++ {
		wg.Add(1)
		go func(w int) {
			defer wg.Done()
			for i := 0; i < 3000; i++ {
				key := fmt.Sprintf("repo|u|P|w%d-%d", w, i)
				r.store_(key, testDecision("r"), time.Minute)
				r.cached(key)
				r.cached(fmt.Sprintf("repo|u|P|w%d-%d", (w+1)%4, i))
			}
		}(w)
	}
	wg.Wait()
	if got := len(r.cache); got > maxCacheEntries {
		t.Fatalf("동시 삽입 후 len(cache) = %d, want <= %d", got, maxCacheEntries)
	}
}
