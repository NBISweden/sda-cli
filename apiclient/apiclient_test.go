package apiclient

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

func TestNew_V2NotYetImplemented(t *testing.T) {
	_, err := New(Config{BaseURL: "http://x", Token: "t"}, "v2")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not yet implemented")
}

func TestNew_UnknownVersion(t *testing.T) {
	_, err := New(Config{BaseURL: "http://x", Token: "t"}, "v3")
	require.Error(t, err)
	assert.Contains(t, err.Error(), `unsupported --api-version "v3"`)
}
