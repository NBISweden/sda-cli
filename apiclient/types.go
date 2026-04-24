// Package apiclient defines the SDA download API client interface and
// shared types. v1 and v2 implementations live in v1.go and v2.go.
package apiclient

// File is the shared metadata type for a dataset file. Fields match v1's
// wire shape. v2 has additional fields (checksums array, downloadUrl)
// that are handled inside V2Client's conversion layer and surfaced
// through this same type where applicable (see #675/#677).
type File struct {
	FileID                    string `json:"fileId"`
	DisplayFileName           string `json:"displayFileName"`
	FilePath                  string `json:"filePath"`
	DecryptedFileSize         int    `json:"decryptedFileSize"`
	DecryptedFileChecksum     string `json:"decryptedFileChecksum"`
	DecryptedFileChecksumType string `json:"decryptedFileChecksumType"`
	// DownloadURL is v2-only (server-provided relative URL).
	// Empty on v1 File values.
	DownloadURL string `json:"-"`
}

// Checksum is the v2 checksum element. Included for completeness; v1
// does not populate it. Used by v2 types in #675.
type Checksum struct {
	Type     string `json:"type"`
	Checksum string `json:"checksum"`
}

// DatasetInfo is the v2 /datasets/{id} metadata response. v1 has no
// equivalent; V1Client.DatasetInfo returns ErrNotSupportedOnV1.
type DatasetInfo struct {
	DatasetID string `json:"datasetId"`
	FileCount int    `json:"files"`
	Size      int64  `json:"size"`
}

// ListFilesOptions carries v2-only filter options. V1Client returns
// ErrNotSupportedOnV1 if ExactPath or PathPrefix is set.
type ListFilesOptions struct {
	ExactPath  string // filePath (v2 exact-match)
	PathPrefix string // pathPrefix (v2 recursive)

	// LegacyV1PubKey, when non-empty, is forwarded as the Client-Public-Key
	// HTTP header on v1 /files list requests. Preserves the exact wire
	// behavior of the original download.GetFilesInfo where fileCase forwarded
	// the caller's pubKeyBase64 on listing. V2 ignores this field. Removed
	// together with V1Client in #677.
	LegacyV1PubKey string
}
