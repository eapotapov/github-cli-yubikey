package yubikey

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/cli/cli/v2/internal/ghinstance"
)

// CredentialHTTPClient is the client for requests that carry credentials when no session protects them yet: the OAuth
// sign-in and token exchange, whose requests and responses hold refresh tokens, and the check of which account a
// fresh access token belongs to.
//
// It is deliberately not gh's usual client, which takes its routing from places a local program can change:
//
//   - gh's http_unix_socket setting sends every request, HTTPS included, to a local socket without TLS.
//   - A proxy named in the environment sees the connection. That only tunnels TLS, but combined with a certificate
//     bundle named in the environment (SSL_CERT_FILE), which Go honours, it can read the traffic.
//
// So this client ignores gh's configuration, uses no proxy, and logs nothing. It connects straight to the host it is
// asked for. The cost is that these requests do not work from behind a mandatory HTTP proxy.
func CredentialHTTPClient(timeout time.Duration) *http.Client {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.Proxy = nil
	return &http.Client{Transport: transport, Timeout: timeout}
}

// TokenOwner asks the server which account token belongs to. It goes to the host's own API address, ignoring gh's
// api_host setting: that setting is in a file anything can edit, and following it would send the token wherever the
// file says and let the answer be forged. Pass a client from CredentialHTTPClient.
func TokenOwner(httpClient *http.Client, hostname, token string) (string, error) {
	req, err := http.NewRequest(http.MethodGet, ghinstance.RESTPrefix(hostname)+"user", nil)
	if err != nil {
		return "", err
	}
	req.Header.Set("Authorization", "token "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	resp, err := httpClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%s answered HTTP %d", hostname, resp.StatusCode)
	}
	var user struct {
		Login string `json:"login"`
	}
	if err := json.NewDecoder(io.LimitReader(resp.Body, 1<<20)).Decode(&user); err != nil || user.Login == "" {
		return "", errors.New("unexpected answer from the server")
	}
	return user.Login, nil
}
