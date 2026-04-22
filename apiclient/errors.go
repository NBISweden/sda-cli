package apiclient

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime"
	"net/http"
)

// ErrNotSupportedOnV1 indicates the caller requested a feature unavailable
// on the v1 download API — either a method with no v1 endpoint
// (DatasetInfo) or a v2-only option (ListFilesOptions.ExactPath /
// .PathPrefix).
var ErrNotSupportedOnV1 = errors.New("operation not supported on v1 download API; use --api-version v2")

// errorBodyReadLimit caps how much of a non-2xx response body is read into
// memory. 8 KiB is plenty for any realistic RFC 9457 Problem Details
// document while bounding allocation if a hostile or misconfigured server
// streams a huge payload.
const errorBodyReadLimit = 8 << 10

// ProblemDetails is the RFC 9457 Problem Details shape.
// All fields are optional per the spec.
type ProblemDetails struct {
	Type     string `json:"type,omitempty"`
	Title    string `json:"title,omitempty"`
	Status   int    `json:"status,omitempty"`
	Detail   string `json:"detail,omitempty"`
	Instance string `json:"instance,omitempty"`
}

// APIError is the typed error returned from a non-2xx HTTP response.
// StatusCode lets callers discriminate on the response code (e.g. 403
// handling) via errors.As without substring-matching the message.
// Problem is populated when the body parses as RFC 9457 Problem Details;
// nil for non-Problem bodies (HTML error pages, empty bodies, invalid JSON).
type APIError struct {
	StatusCode int
	Problem    *ProblemDetails
	// Body is the truncated raw response body, bounded for safe display.
	Body string
	msg  string
}

func (e *APIError) Error() string { return e.msg }

// parseErrorResponse converts a non-2xx HTTP response into an *APIError.
// Tries Problem Details first (Content-Type: application/problem+json
// or application/json). Falls back to "server returned status N: <body>"
// when parsing fails or the body isn't Problem Details. Always safe even
// on empty or malformed bodies.
//
// Always consumes and closes resp.Body. The body read is capped at
// errorBodyReadLimit to bound allocation from a hostile server.
func parseErrorResponse(resp *http.Response) error {
	defer resp.Body.Close() //nolint:errcheck
	body, _ := io.ReadAll(io.LimitReader(resp.Body, errorBodyReadLimit))

	apiErr := &APIError{
		StatusCode: resp.StatusCode,
		Body:       truncate(string(body), 200),
	}

	if isJSONContentType(resp.Header.Get("Content-Type")) && len(body) > 0 {
		var pd ProblemDetails
		if err := json.Unmarshal(body, &pd); err == nil {
			apiErr.Problem = &pd
			apiErr.msg = formatProblemDetails(resp.StatusCode, pd, apiErr.Body)

			return apiErr
		}
		// JSON didn't parse; fall through to the raw-body fallback.
	}

	apiErr.msg = fmt.Sprintf("server returned status %d: %s", resp.StatusCode, apiErr.Body)

	return apiErr
}

// isJSONContentType reports whether the media type in ct is
// application/problem+json or application/json. HTTP media types are
// case-insensitive per RFC 7231, so we go through mime.ParseMediaType
// which normalizes the main type to lowercase.
func isJSONContentType(ct string) bool {
	mt, _, err := mime.ParseMediaType(ct)
	if err != nil {
		return false
	}

	return mt == "application/problem+json" || mt == "application/json"
}

// formatProblemDetails picks the best error wording given which
// RFC 9457 fields are populated. Per the spec all fields are optional,
// so we handle the no-Title/no-Detail case by surfacing the truncated
// body sample just like the non-Problem fallback path does.
func formatProblemDetails(status int, pd ProblemDetails, bodySample string) string {
	switch {
	case pd.Title != "" && pd.Detail != "":
		return fmt.Sprintf("%s (%d): %s", pd.Title, status, pd.Detail)
	case pd.Title != "":
		return fmt.Sprintf("%s (%d)", pd.Title, status)
	case pd.Detail != "":
		return fmt.Sprintf("server error %d: %s", status, pd.Detail)
	default:
		return fmt.Sprintf("server returned status %d: %s", status, bodySample)
	}
}

// truncate returns s truncated to at most n bytes. Shared with v2.go's
// non-2xx fallback so message shape is identical everywhere.
func truncate(s string, n int) string {
	if len(s) > n {
		return s[:n]
	}

	return s
}
