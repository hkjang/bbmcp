package policy

import (
	"context"
	"time"
)

// forcedLoad marks the in-memory rule cache as fresh so Evaluate does not hit
// a database in unit tests.
func forcedLoad() time.Time { return time.Now() }

func ctxBackground() context.Context { return context.Background() }
