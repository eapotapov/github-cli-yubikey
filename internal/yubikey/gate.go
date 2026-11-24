// Package yubikey gates gh's GitHub credentials behind a YubiKey.
//
// At rest, the only credential on disk is an OAuth refresh token sealed to a P-256 key that lives in a PIV slot of the
// YubiKey and cannot be extracted. Unsealing it takes the key, its PIN and a touch. `gh auth unlock` does that once,
// trades the refresh token for a short-lived access token and starts a background agent, which keeps the session's
// tokens in memory for a limited time. Every other gh command asks the agent for the access token. When the session ends
// (timer, `gh auth lock`, or the YubiKey being unplugged) the agent forgets the access token and revokes it.
//
// Revocation works by rotation. GitHub's token revocation endpoint cannot be used: it invalidates the refresh token
// along with the access token, which would force a full sign-in after every session. But GitHub also invalidates an
// access token the moment its refresh token is spent. So the agent keeps the refresh token in memory for the length of
// the session and, at the end, spends it: the session's access token dies, the replacement refresh token is sealed to
// the YubiKey (sealing needs only the public key), and the replacement access token is discarded unused.
//
// The refresh token never travels over the agent's socket. `gh auth unlock` starts the agent itself and passes the
// tokens through a pipe only the two processes share, because anything listening on a socket path could be an impostor.
// The socket only serves requests: the access token, the session's status, and ending the session.
//
// The gate is off unless Enable is called, which only the gh binary's main function does. That keeps the rest of the
// code base, and its tests, on the upstream credential paths.
package yubikey

import (
	"net/url"
	"path/filepath"
	"sync/atomic"
	"time"

	ghConfig "github.com/cli/go-gh/v2/pkg/config"
)

const (
	// SlotKey is the PIV slot holding the sealing key: retired key management slot 2.
	SlotKey = 0x83

	// DefaultSessionTTL is how long `gh auth unlock` opens a session for when no duration is given.
	DefaultSessionTTL = time.Hour

	// TokenSource is the Credential source reported for a token served by the agent.
	TokenSource = "yubikey-session"
)

var enabled atomic.Bool

// Enable turns the gate on for the lifetime of the process.
func Enable() { enabled.Store(true) }

// Enabled reports whether credentials are gated behind the YubiKey.
func Enabled() bool { return enabled.Load() }

// runtimeDir holds the agent's socket and log. Listen makes it private to the current user.
func runtimeDir() string {
	return filepath.Join(ghConfig.StateDir(), "yubikey")
}

// SocketPath is where the agent for hostname listens. Each unlocked host has its own agent process.
func SocketPath(hostname string) string {
	return socketPathIn(runtimeDir(), hostname)
}

func socketPathIn(dir, hostname string) string {
	return filepath.Join(dir, socketPrefix+url.PathEscape(hostname)+socketSuffix)
}

const (
	socketPrefix = "agent-"
	socketSuffix = ".sock"
)

// LogPath is where the agent records session events. It never contains tokens.
func LogPath() string {
	return filepath.Join(runtimeDir(), "agent.log")
}

func vaultDir() string {
	return filepath.Join(ghConfig.ConfigDir(), "yubikey")
}
