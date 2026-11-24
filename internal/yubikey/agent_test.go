package yubikey

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/json"
	"errors"
	"io"
	"net"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type revocation struct {
	token, refreshToken, vaultID string
}

type agentHarness struct {
	client Client
	dir    string
	done   chan struct{}
	cancel context.CancelFunc

	mu      sync.Mutex
	now     time.Time
	present bool
	revoked []revocation
	failing bool
	// gate, when set, blocks revocation until it is closed, to hold a session in the middle of ending.
	gate chan struct{}
}

func (h *agentHarness) set(fn func()) {
	h.mu.Lock()
	defer h.mu.Unlock()
	fn()
}

func (h *agentHarness) revocations() []revocation {
	h.mu.Lock()
	defer h.mu.Unlock()
	return append([]revocation{}, h.revoked...)
}

func (h *agentHarness) waitStopped(t *testing.T) {
	t.Helper()
	select {
	case <-h.done:
	case <-time.After(5 * time.Second):
		t.Fatal("agent did not stop")
	}
}

func socketDir(t *testing.T) string {
	t.Helper()
	// Unix socket paths are short-limited, and t.TempDir() is too deep on macOS.
	dir, err := os.MkdirTemp("/tmp", "ghyk")
	require.NoError(t, err)
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}

var testClock = time.Date(2026, 11, 24, 12, 0, 0, 0, time.UTC)

func testHandoff(t *testing.T, host, token string, ttl time.Duration) Handoff {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	expires := testClock.Add(8 * time.Hour)
	return Handoff{
		Session: Session{Hostname: host, Username: "monalisa", Token: token, Deadline: testClock.Add(ttl), TokenExpiresAt: &expires},
		Renewal: Renewal{RefreshToken: "refresh-" + token, Recipient: key.PublicKey().Bytes(), VaultID: "vault-" + token},
	}
}

// startAgent runs an agent for the handoff in dir, the way `gh auth agent` does after reading its standard input.
func startAgent(t *testing.T, dir string, h Handoff) *agentHarness {
	t.Helper()
	harness := &agentHarness{
		client:  Client{Dir: dir},
		dir:     dir,
		done:    make(chan struct{}),
		now:     testClock,
		present: true,
	}
	agent := &Agent{
		PollInterval: 5 * time.Millisecond,
		Revoke: func(s Session, r Renewal) error {
			harness.mu.Lock()
			gate := harness.gate
			harness.mu.Unlock()
			if gate != nil {
				<-gate
			}
			harness.mu.Lock()
			defer harness.mu.Unlock()
			if harness.failing {
				return errors.New("server unreachable")
			}
			harness.revoked = append(harness.revoked, revocation{s.Token, r.RefreshToken, r.VaultID})
			return nil
		},
		KeyPresent: func() (bool, error) {
			harness.mu.Lock()
			defer harness.mu.Unlock()
			return harness.present, nil
		},
		now: func() time.Time {
			harness.mu.Lock()
			defer harness.mu.Unlock()
			return harness.now
		},
	}
	l, err := Listen(dir, h.Session.Hostname)
	require.NoError(t, err)
	ctx, cancel := context.WithCancel(context.Background())
	harness.cancel = cancel
	go func() {
		defer close(harness.done)
		_ = agent.Serve(ctx, l, h)
	}()
	t.Cleanup(func() {
		cancel()
		<-harness.done
	})
	// Serve installs the session asynchronously; wait until it answers.
	require.Eventually(t, func() bool {
		_, ok := harness.client.Session(h.Session.Hostname)
		return ok
	}, 2*time.Second, 5*time.Millisecond)
	return harness
}

func TestAgentServesSessionUntilLocked(t *testing.T) {
	h := startAgent(t, socketDir(t), testHandoff(t, "github.com", "tok1", time.Hour))

	s, ok := h.client.Session("github.com")
	require.True(t, ok)
	assert.Equal(t, "tok1", s.Token)
	assert.Equal(t, "monalisa", s.Username)

	_, ok = h.client.Session("example.com")
	assert.False(t, ok, "a session is per host")

	listed := h.client.Sessions()
	require.Len(t, listed, 1)
	assert.Empty(t, listed[0].Token, "status must not leak the token")

	ended := h.client.Lock("")
	require.Len(t, ended, 1)
	assert.Equal(t, "monalisa", ended[0].Username)
	assert.True(t, ended[0].Revoked)
	assert.Equal(t, []revocation{{"tok1", "refresh-tok1", "vault-tok1"}}, h.revocations(), "the token is revoked with its own refresh token")

	_, ok = h.client.Session("github.com")
	assert.False(t, ok)
	h.waitStopped(t)
	assert.Len(t, h.revocations(), 1, "stopping after a lock does not revoke twice")
	_, err := os.Stat(socketPathIn(h.dir, "github.com"))
	assert.True(t, os.IsNotExist(err), "the agent removes its socket when it exits")
}

func TestAgentEndsSessionAtDeadline(t *testing.T) {
	h := startAgent(t, socketDir(t), testHandoff(t, "github.com", "tok1", time.Hour))

	h.set(func() { h.now = h.now.Add(59 * time.Minute) })
	time.Sleep(50 * time.Millisecond)
	_, ok := h.client.Session("github.com")
	require.True(t, ok, "still inside the time limit")

	h.set(func() { h.now = h.now.Add(time.Minute) })
	h.waitStopped(t)
	assert.Equal(t, []revocation{{"tok1", "refresh-tok1", "vault-tok1"}}, h.revocations())
	_, ok = h.client.Session("github.com")
	assert.False(t, ok)
}

func TestAgentEndsSessionWhenKeyIsRemoved(t *testing.T) {
	h := startAgent(t, socketDir(t), testHandoff(t, "github.com", "tok1", time.Hour))
	h.set(func() { h.present = false })
	h.waitStopped(t)
	assert.Equal(t, []revocation{{"tok1", "refresh-tok1", "vault-tok1"}}, h.revocations())
}

func TestAgentRevokesOnShutdown(t *testing.T) {
	h := startAgent(t, socketDir(t), testHandoff(t, "github.com", "tok1", time.Hour))
	h.cancel()
	h.waitStopped(t)
	assert.Equal(t, []revocation{{"tok1", "refresh-tok1", "vault-tok1"}}, h.revocations())
}

func TestAgentReportsFailedRevocation(t *testing.T) {
	h := startAgent(t, socketDir(t), testHandoff(t, "github.com", "tok1", time.Hour))
	h.set(func() { h.failing = true })

	ended := h.client.Lock("github.com")
	require.Len(t, ended, 1)
	assert.False(t, ended[0].Revoked)
	assert.Contains(t, ended[0].RevokeError, "server unreachable")
	require.NotNil(t, ended[0].TokenExpiresAt, "the caller is told how long the unrevoked token keeps working")
	_, ok := h.client.Session("github.com")
	assert.False(t, ok, "the session ends even when revocation fails")
}

func TestAgentLockWaitsForARevocationAlreadyInProgress(t *testing.T) {
	h := startAgent(t, socketDir(t), testHandoff(t, "github.com", "tok1", time.Hour))
	gate := make(chan struct{})
	h.set(func() { h.gate = gate; h.failing = true })

	// The deadline passes; the agent starts ending the session and is held in the middle of revoking.
	h.set(func() { h.now = h.now.Add(2 * time.Hour) })
	require.Eventually(t, func() bool {
		_, ok := h.client.Session("github.com")
		return !ok
	}, 2*time.Second, 5*time.Millisecond, "the session stops being served as soon as ending starts")

	// A lock request made meanwhile must not come back saying nothing was unlocked.
	answer := make(chan []EndedSession, 1)
	go func() { answer <- h.client.Lock("github.com") }()
	select {
	case got := <-answer:
		t.Fatalf("lock returned before revocation finished: %+v", got)
	case <-time.After(150 * time.Millisecond):
	}

	close(gate)
	select {
	case ended := <-answer:
		require.Len(t, ended, 1, "the caller learns the outcome of the revocation that was in progress")
		assert.False(t, ended[0].Revoked)
		assert.Contains(t, ended[0].RevokeError, "server unreachable")
	case <-time.After(5 * time.Second):
		t.Fatal("lock never returned")
	}
}

func TestAgentKeepsItsSocketUntilRevocationFinishes(t *testing.T) {
	h := startAgent(t, socketDir(t), testHandoff(t, "github.com", "tok1", time.Hour))
	gate := make(chan struct{})
	h.set(func() { h.gate = gate })

	first := make(chan []EndedSession, 1)
	go func() { first <- h.client.Lock("github.com") }()
	require.Eventually(t, func() bool {
		_, ok := h.client.Session("github.com")
		return !ok
	}, 2*time.Second, 5*time.Millisecond)

	// Many polling ticks pass while the first request is still revoking. The agent must stay reachable, so a second
	// request waits for the same outcome and is not told that nothing was unlocked.
	time.Sleep(100 * time.Millisecond)
	second := make(chan []EndedSession, 1)
	go func() { second <- h.client.Lock("github.com") }()
	select {
	case got := <-second:
		t.Fatalf("second lock returned before revocation finished: %+v", got)
	case <-time.After(150 * time.Millisecond):
	}

	close(gate)
	for _, answer := range []chan []EndedSession{first, second} {
		select {
		case ended := <-answer:
			require.Len(t, ended, 1)
			assert.True(t, ended[0].Revoked)
		case <-time.After(5 * time.Second):
			t.Fatal("lock never returned")
		}
	}
	h.waitStopped(t)
	assert.Len(t, h.revocations(), 1, "the token is revoked once")
}

func TestClientLockReportsAnAgentThatDoesNotConfirm(t *testing.T) {
	dir := socketDir(t)
	l, err := net.Listen("unix", socketPathIn(dir, "github.com"))
	require.NoError(t, err)
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			conn.Close() // accepts, then says nothing
		}
	}()
	ended := Client{Dir: dir}.Lock("")
	require.Len(t, ended, 1, "an unconfirmed lock is never reported as nothing to lock")
	assert.Equal(t, "github.com", ended[0].Hostname)
	assert.False(t, ended[0].Revoked)
	assert.NotEmpty(t, ended[0].RevokeError)
}

// rawRequest sends arbitrary JSON to an agent socket, as a hostile local process could.
func rawRequest(t *testing.T, path string, payload any) string {
	t.Helper()
	conn, err := net.Dial("unix", path)
	require.NoError(t, err)
	defer conn.Close()
	require.NoError(t, json.NewEncoder(conn).Encode(payload))
	raw, err := io.ReadAll(conn)
	require.NoError(t, err)
	return string(raw)
}

func TestAgentSocketCannotReadOrReplaceTheRenewal(t *testing.T) {
	h := startAgent(t, socketDir(t), testHandoff(t, "github.com", "tok1", time.Hour))
	path := socketPathIn(h.dir, "github.com")

	// Nothing a client can read back contains the refresh token.
	for _, op := range []string{opGet, opStatus} {
		assert.NotContains(t, rawRequest(t, path, map[string]any{"op": op, "hostname": "github.com"}), "refresh-tok1")
	}

	// A request that tries to install a session, as the protocol once allowed, changes nothing. Nor is there any
	// flag a caller can set to make the agent skip the credential lock.
	evil := map[string]any{
		"op":      "put",
		"session": map[string]any{"hostname": "github.com", "username": "monalisa", "token": "evil", "deadline": testClock.Add(time.Hour)},
		"renewal": map[string]any{"refresh_token": "evil-refresh", "recipient": []byte{4}, "vault_id": "evil"},
	}
	assert.Contains(t, rawRequest(t, path, evil), "unknown operation")
	s, ok := h.client.Session("github.com")
	require.True(t, ok)
	assert.Equal(t, "tok1", s.Token)

	// Hammering the socket does not keep a session alive once the key is gone.
	h.set(func() { h.present = false })
	for i := 0; i < 20; i++ {
		// The agent may close its socket at any point in this loop; a refused or cut connection is fine.
		if conn, err := net.Dial("unix", path); err == nil {
			_ = json.NewEncoder(conn).Encode(evil)
			_, _ = io.ReadAll(conn)
			conn.Close()
		}
	}
	h.waitStopped(t)
	assert.Equal(t, []revocation{{"tok1", "refresh-tok1", "vault-tok1"}}, h.revocations(), "the genuine credential is the one revoked")
}

func TestAgentsForDifferentHostsAreIndependent(t *testing.T) {
	dir := socketDir(t)
	a := startAgent(t, dir, testHandoff(t, "github.com", "tok1", time.Hour))
	b := startAgent(t, dir, testHandoff(t, "example.com", "tok2", time.Hour))
	assert.Len(t, a.client.Sessions(), 2)

	ended := a.client.Lock("github.com")
	require.Len(t, ended, 1)
	a.waitStopped(t)
	s, ok := b.client.Session("example.com")
	require.True(t, ok, "locking one host leaves the other unlocked")
	assert.Equal(t, "tok2", s.Token)

	assert.Len(t, b.client.Lock(""), 1)
	b.waitStopped(t)
	assert.Empty(t, b.client.Sessions())
}

func TestNewAgentTakesOverTheSocketAndOldOneLeavesItAlone(t *testing.T) {
	dir := socketDir(t)
	old := startAgent(t, dir, testHandoff(t, "github.com", "old", time.Hour))
	fresh := startAgent(t, dir, testHandoff(t, "github.com", "new", time.Hour))

	s, ok := fresh.client.Session("github.com")
	require.True(t, ok)
	assert.Equal(t, "new", s.Token, "clients reach the newest agent")

	// The displaced agent ends on its own and must not remove the socket that now belongs to the new one.
	old.cancel()
	old.waitStopped(t)
	s, ok = fresh.client.Session("github.com")
	require.True(t, ok, "the new agent's socket survives the old agent's exit")
	assert.Equal(t, "new", s.Token)
}

func TestHandoffValidate(t *testing.T) {
	good := testHandoff(t, "github.com", "tok1", time.Hour)
	require.NoError(t, good.Validate(testClock))

	cases := map[string]func(h *Handoff){
		"no token":         func(h *Handoff) { h.Session.Token = "" },
		"no host":          func(h *Handoff) { h.Session.Hostname = "" },
		"past deadline":    func(h *Handoff) { h.Session.Deadline = testClock.Add(-time.Minute) },
		"no refresh token": func(h *Handoff) { h.Renewal.RefreshToken = "" },
		"no vault id":      func(h *Handoff) { h.Renewal.VaultID = "" },
		"bad recipient":    func(h *Handoff) { h.Renewal.Recipient = []byte{4} },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			h := good
			mutate(&h)
			assert.Error(t, h.Validate(testClock))
		})
	}

	t.Run("serve refuses an invalid handoff", func(t *testing.T) {
		l, err := Listen(socketDir(t), "github.com")
		require.NoError(t, err)
		bad := good
		bad.Renewal.RefreshToken = ""
		assert.Error(t, (&Agent{}).Serve(context.Background(), l, bad))
	})
}

func TestClientWithoutAgent(t *testing.T) {
	client := Client{Dir: t.TempDir()}
	_, ok := client.Session("github.com")
	assert.False(t, ok)
	assert.Empty(t, client.Lock(""))
	assert.Empty(t, client.Lock("github.com"))
	assert.Empty(t, client.Sessions())
}

func TestClientIgnoresAnImpostorThatAnswersNonsense(t *testing.T) {
	dir := socketDir(t)
	l, err := net.Listen("unix", socketPathIn(dir, "github.com"))
	require.NoError(t, err)
	defer l.Close()
	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			// Claims a session for a different host and with no token.
			_, _ = io.WriteString(conn, `{"session":{"hostname":"example.com","username":"mallory","deadline":"2099-01-01T00:00:00Z"}}`+"\n")
			conn.Close()
		}
	}()
	_, ok := Client{Dir: dir}.Session("github.com")
	assert.False(t, ok)
}

func TestListenIsPrivateEvenWithALooseDirectory(t *testing.T) {
	dir := socketDir(t)
	require.NoError(t, os.Chmod(dir, 0o777))

	l, err := Listen(dir, "github.com")
	require.NoError(t, err)
	defer l.Close()

	info, err := os.Stat(dir)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o700), info.Mode().Perm())
	info, err = os.Stat(filepath.Join(dir, "agent-github.com.sock"))
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
}
