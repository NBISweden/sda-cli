package downloadclient

import (
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNew_V1(t *testing.T) {
	client, err := New(Config{BaseURL: "http://x", Token: "t"}, "v1")
	require.NoError(t, err)
	_, ok := client.(*V1Client)
	assert.True(t, ok)
}

func TestNew_V2(t *testing.T) {
	client, err := New(Config{BaseURL: "http://x", Token: "t"}, "v2")
	require.NoError(t, err)
	require.NotNil(t, client)
	_, ok := client.(*V2Client)
	assert.True(t, ok, "expected *V2Client, got %T", client)
}

func TestNew_UnknownVersion(t *testing.T) {
	_, err := New(Config{BaseURL: "http://x", Token: "t"}, "v3")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unsupported --api-version "v3"`)
}

func TestNew_ValidatesConfig(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{"empty BaseURL", Config{Token: "t"}, "Config.BaseURL is required"},
		{"unparseable BaseURL", Config{BaseURL: "not a url", Token: "t"}, "invalid Config.BaseURL"},
		{"missing scheme", Config{BaseURL: "example.org", Token: "t"}, "invalid Config.BaseURL"},
		{"empty Token", Config{BaseURL: "http://x"}, "Config.Token is required"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := New(tc.cfg, "v1")
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.want)
		})
	}
}
