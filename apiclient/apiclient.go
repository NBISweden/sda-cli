package apiclient

import (
	"context"
	"fmt"
	"io"

	"go.nhat.io/cookiejar"
)

// Config holds per-call configuration.
type Config struct {
	BaseURL string // e.g. "https://download.example.org"
	Token   string // bearer token (raw, no "Bearer " prefix)
	Version string // sda-cli version; SDA-Client-Version on v1, User-Agent "sda-cli/<version>" on v2
}

// DownloadRequest describes one file to fetch.
type DownloadRequest struct {
	// DatasetID — always required.
	DatasetID string
	// UserArg is the raw positional arg from the CLI: either a file path
	// (may contain "/" or end in ".c4gh") or a fileId. Implementations
	// disambiguate internally.
	UserArg string
	// PublicKeyBase64 is the recipient public key (v2 preferred: base64
	// of raw 32-byte X25519 key; v2 legacy: base64 of full PEM text; v1
	// uses whatever download.helpers.GetPublicKey64 produced).
	PublicKeyBase64 string
}

// DownloadResult bundles the three things a caller needs after a successful
// DownloadFile: the canonical File metadata (authoritative filename), a
// ReadCloser streaming the Crypt4GH-encrypted bytes, and the server's
// Content-Length (0 when absent). Callers must close Body.
type DownloadResult struct {
	File          File
	Body          io.ReadCloser
	ContentLength int64
}

// Client is the SDA download API abstraction for list-family operations
// and file download.
type Client interface {
	ListDatasets(ctx context.Context) ([]string, error)
	ListFiles(ctx context.Context, datasetID string, opts ListFilesOptions) ([]File, error)
	DatasetInfo(ctx context.Context, datasetID string) (DatasetInfo, error)

	// DownloadFile resolves req.UserArg against the dataset and returns a
	// DownloadResult. The returned File is the authoritative name to use
	// for the on-disk output — callers must not derive the output path
	// from req.UserArg, because UserArg may be a fileId with no
	// relationship to the filename.
	DownloadFile(ctx context.Context, req DownloadRequest) (DownloadResult, error)
}

// Option customises the Client returned by New. Options only affect the
// versions they apply to; unknown options are silently ignored by
// versions that do not honour them (WithV1CookieJar is v1-only).
type Option func(*clientOpts)

type clientOpts struct {
	v1CookieJar *cookiejar.PersistentJar
}

// WithV1CookieJar hands V1Client an externally-managed persistent cookie
// jar instead of letting it lazy-init its own. Required when the caller
// (e.g. download/download.go) also runs the legacy downloadFile path so
// metadata listing and /s3 transfer share the same in-memory jar and
// avoid clobbering each other via AutoSync to the shared on-disk file.
func WithV1CookieJar(jar *cookiejar.PersistentJar) Option {
	return func(o *clientOpts) { o.v1CookieJar = jar }
}

// ValidateVersion returns the same error shape as New for a given
// version string without constructing a client. Callers can use it to
// fail fast on unsupported versions before doing other setup work
// (e.g. cookie-jar init) that is wasted when the command is going to
// error out anyway.
func ValidateVersion(version string) error {
	switch version {
	case "v1", "v2":
		return nil
	default:
		return fmt.Errorf("unsupported --api-version %q (v1 or v2)", version)
	}
}

// New returns a Client for the requested version. "v1" returns a V1Client;
// "v2" returns a V2Client (minimal — some methods are stubs until later PRs
// of issue #663, see V2Client doc).
func New(cfg Config, version string, opts ...Option) (Client, error) {
	if err := ValidateVersion(version); err != nil {
		return nil, err
	}

	var o clientOpts
	for _, opt := range opts {
		opt(&o)
	}

	switch version {
	case "v1":
		return NewV1Client(cfg, o.v1CookieJar), nil
	case "v2":
		return NewV2Client(cfg), nil
	default:
		// Unreachable: ValidateVersion returned nil, so version is "v1" or "v2".
		return nil, fmt.Errorf("unsupported --api-version %q", version)
	}
}
