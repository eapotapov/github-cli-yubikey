package config

import (
	"errors"
	"fmt"
	"path/filepath"

	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/internal/yubikey"
	ghConfig "github.com/cli/go-gh/v2/pkg/config"
)

// CredentialLockPath is the cross-process lock that login, logout and token refresh hold while they change stored
// credentials. `gh auth unlock` takes the same lock, so it cannot interleave with them.
func CredentialLockPath() string {
	return filepath.Join(ghConfig.StateDir(), refreshLockFile)
}

// This file holds the credential paths used when gh is gated behind a YubiKey (see the yubikey package). In that mode
// AuthConfig never reads or writes a token in the keyring, the config file or the environment. The only stored
// credential is a refresh token sealed to the YubiKey, and the only usable token is the one the session agent holds
// while an account is unlocked.

// errGateNeedsExpiring explains why a token that cannot be refreshed is refused: there would be nothing to seal that
// the server could later expire.
var errGateNeedsExpiring = errors.New("this build of gh only stores expiring credentials protected by a YubiKey; " +
	"sign in with a web browser (`gh auth login --web`), not with a pasted token")

// errGateLockUnavailable is returned instead of changing stored credentials without the credential lock. Upstream
// proceeds without the lock as a convenience; here that would let a sign-in or sign-out interleave with an unlock or
// with an agent ending a session, each of which spends a single-use refresh token.
var errGateLockUnavailable = errors.New("another gh process is changing credentials, or the credential lock is unavailable; try again")

// gatedSession returns the agent's session for hostname when it belongs to the host's active user.
func (c *AuthConfig) gatedSession(hostname string) (yubikey.Session, bool) {
	user, err := c.ActiveUser(hostname)
	if err != nil {
		return yubikey.Session{}, false
	}
	return gatedSessionForUser(hostname, user)
}

// gatedSessionForUser returns the agent's session for hostname when it belongs to user and user is still logged in.
func gatedSessionForUser(hostname, user string) (yubikey.Session, bool) {
	session, ok := yubikey.Client{}.Session(hostname)
	if !ok || user == "" || session.Username != user || !yubikey.HasVault(hostname, user) {
		return yubikey.Session{}, false
	}
	return session, true
}

// gatedActiveToken is ActiveToken under the gate: the session token, or nothing while locked.
func (c *AuthConfig) gatedActiveToken(hostname string) gh.Credential {
	session, ok := c.gatedSession(hostname)
	if !ok {
		return gh.Credential{Source: gh.TokenSourceDefault}
	}
	return gh.Credential{Source: yubikey.TokenSource, Token: session.Token}
}

// gatedTokenForUser is TokenForUser under the gate.
func (c *AuthConfig) gatedTokenForUser(hostname, user string) (gh.Credential, error) {
	session, ok := gatedSessionForUser(hostname, user)
	if !ok {
		return gh.Credential{Source: gh.TokenSourceDefault}, fmt.Errorf("%s account %s is locked; run `gh auth unlock`", hostname, user)
	}
	return gh.Credential{Source: yubikey.TokenSource, Token: session.Token}, nil
}

// gatedLoginRefreshable is loginRefreshable under the gate. It seals the refresh token to the YubiKey and stores
// nothing else: the access token issued by the login is dropped, so using gh afterwards takes `gh auth unlock`.
func (c *AuthConfig) gatedLoginRefreshable(hostname, username string, credential gh.Credential, gitProtocol string) error {
	if hostname == "" || username == "" {
		return errors.New("hostname and username are required")
	}
	if err := validateRefreshableCredential(credential); err != nil {
		return err
	}
	recipient, err := yubikey.ReadRecipient()
	if err != nil {
		return err
	}
	secret := yubikey.Secret{RefreshToken: credential.RefreshToken}
	if _, err := yubikey.SealVault(hostname, username, recipient, secret, credential.RefreshTokenExpiresAt); err != nil {
		return fmt.Errorf("could not store the credential: %w", err)
	}

	// Drop any token the config file holds in plain text for this account, including the host-level active copy:
	// the sealed refresh token must be the only credential at rest, and tools built on go-gh read these entries
	// directly, without asking gh. The keyring is deliberately left alone; this build never reads it.
	_ = c.cfg.Remove([]string{hostsKey, hostname, oauthTokenKey})
	_ = c.cfg.Remove([]string{hostsKey, hostname, usersKey, username, oauthTokenKey})
	_ = c.cfg.Remove(refreshablePath(hostname, username))

	return c.completeLogin(hostname, username, gitProtocol)
}

// gatedEndSession ends the open session for hostname before a sign-in or sign-out changes the stored credential, so
// the agent revokes the session's token and writes its rotated credential first. The agent takes the credential lock
// to do that, so this must be called before the lock is taken. With a username it only ends that account's session;
// another account on the host may be the one unlocked.
func gatedEndSession(hostname, username string) {
	client := yubikey.Client{}
	if username != "" {
		if session, ok := client.Session(hostname); !ok || session.Username != username {
			return
		}
	}
	client.Lock(hostname)
}

// gatedEndSessionFor ends the session for hostname if it belongs to username, without requiring the account to still
// be signed in. It is the check made after a sign-out has removed the account.
func gatedEndSessionFor(hostname, username string) {
	client := yubikey.Client{}
	for _, session := range client.Sessions() {
		if session.Hostname == hostname && session.Username == username {
			client.Lock(hostname)
		}
	}
}

// gatedForget removes everything the gate keeps for an account, as part of logging out.
func gatedForget(hostname, username string) error {
	return yubikey.DeleteVault(hostname, username)
}
