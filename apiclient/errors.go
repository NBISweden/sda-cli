package apiclient

import "errors"

// ErrNotSupportedOnV1 indicates the caller requested a feature unavailable
// on the v1 download API — either a method with no v1 endpoint
// (DatasetInfo) or a v2-only option (ListFilesOptions.ExactPath /
// .PathPrefix).
var ErrNotSupportedOnV1 = errors.New("operation not supported on v1 download API; use --api-version v2")
