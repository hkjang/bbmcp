package bitbucket

import "errors"

// asAPIError is a tiny wrapper so tests read clearly.
func asAPIError(err error, target **APIError) bool { return errors.As(err, target) }
