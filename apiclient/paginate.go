package apiclient

import (
	"context"
	"fmt"
)

// paginate runs fetch repeatedly until it returns a nil or empty-string
// nextPageToken. The caller's fetch closure is responsible for building
// the URL (with or without ?pageToken=<tok>) based on whether the token
// is nil. The nil-vs-empty-string distinction matters only to fetch;
// paginate treats both as "stop".
//
// Error semantics are all-or-nothing: a mid-loop failure discards pages
// already collected. Partial results from a listing call would be worse
// than a clear error because callers cannot distinguish "empty result"
// from "cut short after page 1".
//
// Context cancellation is checked at the top of each iteration in
// addition to being forwarded to fetch, so a cancelled context stops
// the loop even if a misbehaving server keeps returning tokens quickly.
//
// A buggy or adversarial server that hands back a previously-seen
// nextPageToken is caught and returned as an error; otherwise the loop
// would append forever and OOM the client.
//
// fetch signature:
//
//	ctx         — forwarded context (callers should honor cancellation)
//	pageToken   — nil on first call; populated on subsequent calls
//	returns     — (batch, nextPageToken, error)
func paginate[T any](
	ctx context.Context,
	fetch func(ctx context.Context, pageToken *string) ([]T, *string, error),
) ([]T, error) {
	var all []T
	var token *string // nil = first call
	seen := make(map[string]struct{})
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		batch, next, err := fetch(ctx, token)
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)
		if next == nil || *next == "" {
			return all, nil
		}
		if _, dup := seen[*next]; dup {
			return nil, fmt.Errorf("pagination aborted: server returned repeated pageToken %q", *next)
		}
		seen[*next] = struct{}{}
		token = next
	}
}
