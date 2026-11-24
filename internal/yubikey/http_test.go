package yubikey

import (
	"net/http"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestCredentialHTTPClientIgnoresProxyEnvironment(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://127.0.0.1:1")
	t.Setenv("HTTP_PROXY", "http://127.0.0.1:1")

	client := CredentialHTTPClient(5 * time.Second)
	assert.Equal(t, 5*time.Second, client.Timeout)
	transport, ok := client.Transport.(*http.Transport)
	require.True(t, ok)
	assert.Nil(t, transport.Proxy, "credential requests must not be routed through an environment proxy")
	assert.NotSame(t, http.DefaultTransport, client.Transport, "the shared default transport is not modified")
}
