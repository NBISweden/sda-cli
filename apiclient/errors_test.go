package apiclient

import (
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// parseSynthetic hands a locally-constructed response to parseErrorResponse
// and returns the resulting error. Inlining the response construction into
// the helper avoids bodyclose false positives at each test site —
// parseErrorResponse owns the body lifecycle, not the test.
func parseSynthetic(t *testing.T, status int, contentType, body string) error {
	t.Helper()
	resp := &http.Response{
		StatusCode: status,
		Header:     http.Header{"Content-Type": []string{contentType}},
		Body:       io.NopCloser(strings.NewReader(body)),
	}

	return parseErrorResponse(resp)
}

func TestParseErrorResponse_ValidProblemDetails(t *testing.T) {
	err := parseSynthetic(t, 400, "application/problem+json", `{"type":"about:blank","title":"Bad Request","status":400,"detail":"conflicting filters","instance":"/datasets/x/files"}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Bad Request")
	assert.Contains(t, err.Error(), "conflicting filters")
}

func TestParseErrorResponse_TitleOnly(t *testing.T) {
	err := parseSynthetic(t, 500, "application/problem+json", `{"title":"Internal Server Error","status":500}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "Internal Server Error")
	assert.NotContains(t, err.Error(), "<nil>") // no empty detail
}

func TestParseErrorResponse_DetailOnly(t *testing.T) {
	err := parseSynthetic(t, 400, "application/problem+json", `{"status":400,"detail":"pageToken is invalid"}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "pageToken is invalid")
}

func TestParseErrorResponse_InvalidJSON(t *testing.T) {
	err := parseSynthetic(t, 502, "application/problem+json", `not json`)
	require.Error(t, err)
	// Fall back to "server returned status N" + truncated body.
	assert.Contains(t, err.Error(), "status 502")
	assert.Contains(t, err.Error(), "not json")
}

func TestParseErrorResponse_WrongContentType(t *testing.T) {
	// Server might return text/html for an nginx error page.
	err := parseSynthetic(t, 503, "text/html", "<html>Service Unavailable</html>")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 503")
	// Body still truncated and included as fallback.
	assert.Contains(t, err.Error(), "Service Unavailable")
}

func TestParseErrorResponse_EmptyBody(t *testing.T) {
	err := parseSynthetic(t, 500, "application/problem+json", "")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "status 500")
	// No confusing empty-title output.
}

func TestParseErrorResponse_403Ambiguous(t *testing.T) {
	// Even if Problem Details has very detailed text, a 403 must not
	// distinguish "not found" from "access denied" in client output —
	// the server intentionally collapses them.
	err := parseSynthetic(t, 403, "application/problem+json", `{"title":"Forbidden","status":403,"detail":"resource not found"}`)
	require.Error(t, err)
	// Caller wraps this further for download/list-by-id paths; here we
	// just surface the server's message but also mark it 403.
	assert.Contains(t, err.Error(), "403")
}

func TestParseErrorResponse_APIErrorTyped(t *testing.T) {
	// Exposes StatusCode for typed callers that need to discriminate on
	// the response code (e.g. 403-flatten in V2Client.DownloadFile) without
	// substring-matching the formatted message.
	err := parseSynthetic(t, 403, "application/problem+json", `{"title":"Forbidden","status":403,"detail":"no"}`)
	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, http.StatusForbidden, apiErr.StatusCode)
	require.NotNil(t, apiErr.Problem)
	assert.Equal(t, "Forbidden", apiErr.Problem.Title)
}

func TestParseErrorResponse_StatusOnlyProblemDetails(t *testing.T) {
	// RFC 9457 says all fields are optional. A minimal Problem Details body
	// with only `status` should still be recognized: apiErr.Problem must be
	// populated and the formatted message must not leak raw JSON braces.
	err := parseSynthetic(t, 500, "application/problem+json", `{"status":500}`)
	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr))
	require.NotNil(t, apiErr.Problem)
	assert.Equal(t, 500, apiErr.Problem.Status)
	assert.Contains(t, err.Error(), "500")
}

func TestParseErrorResponse_ContentTypeCaseInsensitive(t *testing.T) {
	// HTTP media types are case-insensitive per RFC 7231. Upper/mixed-case
	// Content-Type must still trigger Problem Details recognition.
	err := parseSynthetic(t, 400, "Application/Problem+JSON; charset=UTF-8", `{"title":"Bad Request","detail":"x","status":400}`)
	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr))
	require.NotNil(t, apiErr.Problem)
	assert.Equal(t, "Bad Request", apiErr.Problem.Title)
	assert.Contains(t, err.Error(), "Bad Request")
}

func TestParseErrorResponse_APIErrorTyped_FallbackBody(t *testing.T) {
	// Non-Problem bodies still surface as APIError with StatusCode +
	// truncated Body, so callers can typed-check even when the server
	// returns an HTML error page.
	err := parseSynthetic(t, 503, "text/html", "<html>Service Unavailable</html>")
	var apiErr *APIError
	require.True(t, errors.As(err, &apiErr))
	assert.Equal(t, http.StatusServiceUnavailable, apiErr.StatusCode)
	assert.Nil(t, apiErr.Problem)
	assert.Contains(t, apiErr.Body, "Service Unavailable")
}
