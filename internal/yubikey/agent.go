package yubikey

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
)

// Session is an unlocked account: an access token the agent may hand out until Deadline.
type Session struct {
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	// Token is the access token. It is omitted from status replies.
	Token string `json:"token,omitempty"`
	// Deadline is when the agent ends the session on its own.
	Deadline time.Time `json:"deadline"`
	// TokenExpiresAt is when the server stops accepting the token on its own, if known. It matters when the token
	// could not be revoked at the end of the session: a copy of it keeps working until then.
	TokenExpiresAt *time.Time `json:"token_expires_at,omitempty"`
}

// Renewal is what the agent needs to revoke a session's access token when the session ends. GitHub invalidates an
// access token as soon as its refresh token is used, so the agent keeps the refresh token for the length of the
// session and spends it at the end. The replacement refresh token is sealed to Recipient, which takes no PIN or touch,
// and the replacement access token is thrown away.
//
// A Renewal reaches the agent through the handoff pipe and never leaves it: no socket request can set or read it.
type Renewal struct {
	RefreshToken string `json:"refresh_token"`
	// Recipient is the YubiKey's public key, in uncompressed SEC 1 form.
	Recipient []byte `json:"recipient"`
	// VaultID is the identity of the vault file that holds this same refresh token. The replacement refresh token is
	// only stored if that file is still in place.
	VaultID string `json:"vault_id"`
}

// Handoff is everything an agent is started with. `gh auth unlock` writes it to the agent's standard input.
type Handoff struct {
	Session Session `json:"session"`
	Renewal Renewal `json:"renewal"`
}

// Validate checks that the handoff describes a session the agent can serve and later revoke.
func (h Handoff) Validate(now time.Time) error {
	s, r := h.Session, h.Renewal
	if s.Hostname == "" || s.Username == "" || s.Token == "" {
		return errors.New("incomplete session")
	}
	if !now.Round(0).Before(s.Deadline) {
		return errors.New("session deadline is in the past")
	}
	if r.RefreshToken == "" || r.VaultID == "" {
		return errors.New("session cannot be revoked later: incomplete renewal")
	}
	if _, err := ecdh.P256().NewPublicKey(r.Recipient); err != nil {
		return fmt.Errorf("invalid sealing key: %w", err)
	}
	return nil
}

// RevokeFunc invalidates a session's access token with the server by spending its refresh token, and stores the
// replacement refresh token. It takes the credential lock itself. Nothing a socket request says can make it skip the
// lock, because requests are not authenticated; callers that hold the lock must release it before asking an agent to
// end its session.
type RevokeFunc func(s Session, r Renewal) error

type request struct {
	Op       string `json:"op"`
	Hostname string `json:"hostname,omitempty"`
}

type response struct {
	Error   string   `json:"error,omitempty"`
	Session *Session `json:"session,omitempty"`
	// Ended is the session a lock request ended.
	Ended *EndedSession `json:"ended,omitempty"`
}

// EndedSession describes a session the agent closed.
type EndedSession struct {
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	// Revoked reports that the session's access token no longer works on the server.
	Revoked bool `json:"revoked"`
	// RevokeError is why the token could not be revoked, when it could not.
	RevokeError string `json:"revoke_error,omitempty"`
	// TokenExpiresAt is when an unrevoked token expires on the server by itself.
	TokenExpiresAt *time.Time `json:"token_expires_at,omitempty"`
}

// The socket protocol has no request that hands the agent a session or changes one. An agent gets its session once,
// at startup, from the process that started it.
const (
	opGet    = "get"
	opLock   = "lock"
	opStatus = "status"

	// queryTimeout bounds get and status, which every gh command makes. It is short so that something unresponsive
	// on the socket path cannot stall gh for long.
	queryTimeout = 2 * time.Second
	// lockTimeout bounds a lock request, which includes revoking the token with the server.
	lockTimeout = 2 * time.Minute
	// missesBeforeLock is how many consecutive polls must fail to see the YubiKey before the session is ended, so a
	// momentary smart card service hiccup does not lock everything.
	missesBeforeLock = 2
)

// Agent holds one unlocked session in memory and ends it when its time is up, when asked, or when the YubiKey is
// unplugged. Ending the session means no longer serving its token and revoking it with the server. The agent exits
// once the session has ended.
type Agent struct {
	// Revoke invalidates the session's access token with the server.
	Revoke RevokeFunc
	// KeyPresent reports whether the YubiKey is plugged in.
	KeyPresent func() (bool, error)
	// Logf records an event. It must never be given a token.
	Logf func(format string, args ...any)
	// PollInterval is how often the deadline and the YubiKey are checked. Zero means one second.
	PollInterval time.Duration

	now func() time.Time

	mu      sync.Mutex
	session *Session
	renewal Renewal
	misses  int

	// ending makes ending the session happen once. Everyone who asks for the session to end, at the same time or
	// later, waits for that one attempt and gets its outcome, so no caller is told the session is over before the
	// revocation has actually finished.
	ending sync.Once
	ended  *EndedSession
}

func (a *Agent) clock() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

func (a *Agent) logf(format string, args ...any) {
	if a.Logf != nil {
		a.Logf(format, args...)
	}
}

// Listener is the agent's socket. Closing it removes the socket file, but only if the file is still this listener's:
// by then a newer agent may have taken the path over.
type Listener struct {
	net.Listener
	path string
	info os.FileInfo
}

// Close stops listening and removes the socket file if it is still ours.
func (l *Listener) Close() error {
	err := l.Listener.Close()
	if current, statErr := os.Stat(l.path); statErr == nil && os.SameFile(l.info, current) {
		_ = os.Remove(l.path)
	}
	return err
}

// Listen takes over the socket path for hostname inside dir (the default directory when dir is empty) and returns a
// listener only the current user can reach. Whatever was at the path before is replaced: the process starting a new
// agent is the one that just unlocked, so its agent is the one that should answer.
func Listen(dir, hostname string) (*Listener, error) {
	if dir == "" {
		dir = runtimeDir()
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, err
	}
	// MkdirAll leaves an existing directory's mode alone, so tighten it explicitly: nobody else may reach the socket.
	if err := os.Chmod(dir, 0o700); err != nil {
		return nil, err
	}
	path := socketPathIn(dir, hostname)
	_ = os.Remove(path)
	// The socket must never exist with wider permissions, not even for an instant: a connection made in such a
	// window would stay usable after a later chmod.
	l, err := listenPrivate(path)
	if err != nil {
		return nil, err
	}
	if unix, ok := l.(*net.UnixListener); ok {
		// Removal is handled by Listener.Close, which checks the file is still ours.
		unix.SetUnlinkOnClose(false)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, err
	}
	info, err := os.Stat(path)
	if err != nil {
		l.Close()
		return nil, err
	}
	return &Listener{Listener: l, path: path, info: info}, nil
}

// Serve holds the handed-off session and answers requests on l until the session ends or ctx is cancelled. Before
// returning it ends the session if it is still open, revoking its token.
func (a *Agent) Serve(ctx context.Context, l net.Listener, h Handoff) error {
	if err := h.Validate(a.clock()); err != nil {
		l.Close()
		return err
	}
	session := h.Session
	a.mu.Lock()
	a.session = &session
	a.renewal = h.Renewal
	a.mu.Unlock()
	a.logf("session started for %s on %s until %s", session.Username, session.Hostname, session.Deadline.Local().Format(time.RFC3339))

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			wg.Add(1)
			go func() {
				defer wg.Done()
				a.handle(conn)
			}()
		}
	}()

	interval := a.PollInterval
	if interval <= 0 {
		interval = time.Second
	}
	ticker := time.NewTicker(interval)
	defer ticker.Stop()

loop:
	for {
		select {
		case <-ctx.Done():
			break loop
		case <-ticker.C:
			if a.tick() {
				break loop
			}
		}
	}

	// End the session while the socket is still open, so that a lock request arriving now reaches this agent and
	// waits for the outcome, instead of finding no socket and concluding nothing was unlocked.
	a.end("agent stopping")
	l.Close()
	wg.Wait()
	return nil
}

// tick enforces the deadline and YubiKey presence, and reports whether the session is over.
func (a *Agent) tick() (done bool) {
	// Round(0) drops the monotonic reading so the comparison uses wall time, which keeps counting while the machine
	// sleeps. A session must not outlive its deadline just because the laptop lid was closed.
	now := a.clock().Round(0)

	a.mu.Lock()
	open := a.session != nil
	expired := open && !now.Before(a.session.Deadline)
	finished := a.ended != nil
	a.mu.Unlock()
	if !open {
		// A lock request is ending the session. Keep serving until its revocation has finished.
		return finished
	}
	if expired {
		a.end("time limit reached")
		return true
	}

	if a.KeyPresent != nil {
		present, err := a.KeyPresent()
		a.mu.Lock()
		if err != nil || !present {
			a.misses++
		} else {
			a.misses = 0
		}
		misses := a.misses
		a.mu.Unlock()
		if misses >= missesBeforeLock {
			reason := "YubiKey removed"
			if err != nil {
				reason = fmt.Sprintf("YubiKey could not be checked: %v", err)
			}
			a.end(reason)
			return true
		}
	}
	return false
}

// end closes the session and revokes its token, once. The session stops being served before the token is revoked, so
// it is over even if revocation then fails. Every caller gets the outcome of the single attempt, after it finished.
func (a *Agent) end(reason string) *EndedSession {
	a.ending.Do(func() {
		a.mu.Lock()
		session, renewal := a.session, a.renewal
		a.session, a.renewal = nil, Renewal{}
		a.mu.Unlock()
		if session == nil {
			return
		}

		result := &EndedSession{Hostname: session.Hostname, Username: session.Username}
		var err error
		if a.Revoke == nil {
			err = errors.New("revocation is not configured")
		} else {
			err = a.Revoke(*session, renewal)
		}
		if err != nil {
			result.RevokeError = err.Error()
			result.TokenExpiresAt = session.TokenExpiresAt
			a.logf("session ended for %s on %s (%s); token NOT revoked: %v", session.Username, session.Hostname, reason, err)
		} else {
			result.Revoked = true
			a.logf("session ended for %s on %s (%s); token revoked", session.Username, session.Hostname, reason)
		}
		a.mu.Lock()
		a.ended = result
		a.mu.Unlock()
	})
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.ended
}

func (a *Agent) handle(conn net.Conn) {
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(queryTimeout))

	var req request
	if err := json.NewDecoder(io.LimitReader(conn, 1<<16)).Decode(&req); err != nil {
		return
	}
	// Ending a session talks to the server, and may first wait for another gh process to release the credential lock.
	_ = conn.SetDeadline(time.Now().Add(lockTimeout))
	_ = json.NewEncoder(conn).Encode(a.dispatch(req))
}

func (a *Agent) dispatch(req request) response {
	switch req.Op {
	case opGet, opStatus:
		a.mu.Lock()
		var session *Session
		if a.session != nil {
			copied := *a.session
			session = &copied
		}
		a.mu.Unlock()
		if session == nil || !a.clock().Round(0).Before(session.Deadline) {
			return response{}
		}
		if req.Op == opStatus {
			session.Token = ""
		} else if req.Hostname != session.Hostname {
			return response{}
		}
		return response{Session: session}

	case opLock:
		return response{Ended: a.end("locked by user")}
	}
	return response{Error: "unknown operation"}
}

// Client talks to agents.
type Client struct {
	// Dir is where the agents' sockets live. Empty means the default directory.
	Dir string
}

func (c Client) dir() string {
	if c.Dir != "" {
		return c.Dir
	}
	return runtimeDir()
}

// errNoAgent reports that no agent is answering, which means nothing is unlocked.
var errNoAgent = errors.New("no agent running")

func (c Client) call(path string, req request, timeout time.Duration) (response, error) {
	conn, err := net.DialTimeout("unix", path, time.Second)
	if err != nil {
		return response{}, errNoAgent
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return response{}, err
	}
	var resp response
	if err := json.NewDecoder(io.LimitReader(conn, 1<<16)).Decode(&resp); err != nil {
		return response{}, err
	}
	if resp.Error != "" {
		return response{}, errors.New(resp.Error)
	}
	return resp, nil
}

// sockets lists the socket paths of every agent that may be running.
func (c Client) sockets() []string {
	paths, _ := filepath.Glob(filepath.Join(c.dir(), socketPrefix+"*"+socketSuffix))
	sort.Strings(paths)
	return paths
}

// Session returns the unlocked session for hostname. ok is false when the host is locked, including when no agent is
// running or it cannot be reached.
func (c Client) Session(hostname string) (s Session, ok bool) {
	resp, err := c.call(socketPathIn(c.dir(), hostname), request{Op: opGet, Hostname: hostname}, queryTimeout)
	if err != nil || resp.Session == nil || resp.Session.Hostname != hostname || resp.Session.Token == "" {
		return Session{}, false
	}
	return *resp.Session, true
}

// Lock ends the session for hostname, or every session when hostname is empty, and revokes their tokens. It returns
// the sessions that were ended, which is empty when nothing was unlocked. An agent that was reached but did not
// confirm is reported as a session whose token was not revoked, never left out.
//
// The agent takes the credential lock to revoke, so the caller must not be holding it.
func (c Client) Lock(hostname string) []EndedSession {
	paths := c.sockets()
	if hostname != "" {
		paths = []string{socketPathIn(c.dir(), hostname)}
	}
	var ended []EndedSession
	for _, path := range paths {
		resp, err := c.call(path, request{Op: opLock}, lockTimeout)
		switch {
		case errors.Is(err, errNoAgent):
			continue
		case err != nil:
			ended = append(ended, EndedSession{
				Hostname:    hostnameFromSocket(path),
				RevokeError: fmt.Sprintf("the session agent did not confirm: %v", err),
			})
		case resp.Ended != nil:
			ended = append(ended, *resp.Ended)
		}
	}
	return ended
}

func hostnameFromSocket(path string) string {
	name := strings.TrimSuffix(strings.TrimPrefix(filepath.Base(path), socketPrefix), socketSuffix)
	if host, err := url.PathUnescape(name); err == nil {
		return host
	}
	return name
}

// Sessions lists unlocked sessions, without their tokens.
func (c Client) Sessions() []Session {
	var sessions []Session
	for _, path := range c.sockets() {
		resp, err := c.call(path, request{Op: opStatus}, queryTimeout)
		if err != nil || resp.Session == nil {
			continue
		}
		sessions = append(sessions, *resp.Session)
	}
	return sessions
}
