// Package yubikey holds the gh auth commands that manage YubiKey-gated sessions: setup-yubikey, unlock, lock, and the
// hidden agent command that keeps an unlocked session in memory.
package yubikey

import (
	"context"
	"crypto/ecdh"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"slices"
	"strings"
	"syscall"
	"time"

	"github.com/MakeNowJust/heredoc"
	"github.com/cli/cli/v2/internal/authflow"
	"github.com/cli/cli/v2/internal/config"
	"github.com/cli/cli/v2/internal/flock"
	"github.com/cli/cli/v2/internal/gh"
	"github.com/cli/cli/v2/internal/text"
	"github.com/cli/cli/v2/internal/yubikey"
	"github.com/cli/cli/v2/pkg/cmdutil"
	"github.com/cli/cli/v2/pkg/iostreams"
	"github.com/spf13/cobra"
)

// QuietPlainHTTPClient adapts yubikey.CredentialHTTPClient to the factory's plain-client signature, for the sign-in
// commands. The browser sign-in waits on a person, so only its individual requests are bounded, not the flow.
func QuietPlainHTTPClient(*cmdutil.Factory) func() (*http.Client, error) {
	return func() (*http.Client, error) {
		return yubikey.CredentialHTTPClient(60 * time.Second), nil
	}
}

type passwordPrompter interface {
	Password(prompt string) (string, error)
}

func promptPIN(io *iostreams.IOStreams, p passwordPrompter) (string, error) {
	if !io.CanPrompt() {
		return "", errors.New("the YubiKey PIN must be typed at an interactive terminal")
	}
	pin, err := p.Password("YubiKey PIN:")
	if err != nil {
		return "", err
	}
	if pin == "" {
		return "", errors.New("no PIN entered")
	}
	return pin, nil
}

// NewCmdSetup creates `gh auth setup-yubikey`.
func NewCmdSetup(f *cmdutil.Factory) *cobra.Command {
	return &cobra.Command{
		Use:   "setup-yubikey",
		Args:  cobra.ExactArgs(0),
		Short: "Create the key on a YubiKey that protects gh credentials",
		Long: heredoc.Docf(`
			Generate the key that gh credentials are sealed to, in PIV slot %[2]x of the plugged in YubiKey.

			The key is generated on the YubiKey and cannot be copied off it. Using it takes the
			YubiKey's PIN and a touch. Other PIV slots are left untouched, and an existing key in
			slot %[2]x is never replaced.

			Run this once per YubiKey, then %[1]sgh auth login%[1]s.
		`, "`", yubikey.SlotKey),
		RunE: func(cmd *cobra.Command, args []string) error {
			io := f.IOStreams
			cs := io.ColorScheme()

			if existing, err := yubikey.ReadRecipient(); err == nil {
				fmt.Fprintf(io.ErrOut, "%s This YubiKey is already set up (key %s in PIV slot %x)\n",
					cs.SuccessIcon(), yubikey.Fingerprint(existing), yubikey.SlotKey)
				return nil
			} else if !errors.Is(err, yubikey.ErrSlotEmpty) {
				return err
			}

			pin, err := promptPIN(io, f.Prompter)
			if err != nil {
				return err
			}
			key, err := yubikey.GenerateKey(pin)
			if err != nil {
				return err
			}
			fmt.Fprintf(io.ErrOut, "%s Generated key %s in PIV slot %x (PIN and touch required for every use)\n",
				cs.SuccessIcon(), yubikey.Fingerprint(key), yubikey.SlotKey)
			fmt.Fprintf(io.ErrOut, "Next, sign in with: %s\n", cs.Bold("gh auth login"))
			return nil
		},
	}
}

type unlockOptions struct {
	IO       *iostreams.IOStreams
	Config   func() (gh.Config, error)
	Prompter passwordPrompter

	Hostname string
	For      time.Duration
}

// NewCmdUnlock creates `gh auth unlock`.
func NewCmdUnlock(f *cmdutil.Factory) *cobra.Command {
	opts := &unlockOptions{
		IO:       f.IOStreams,
		Config:   f.Config,
		Prompter: f.Prompter,
	}
	cmd := &cobra.Command{
		Use:   "unlock",
		Args:  cobra.ExactArgs(0),
		Short: "Let gh use your GitHub account for a limited time",
		Long: heredoc.Docf(`
			Open a time-limited session, using the YubiKey with its PIN and a touch.

			While the session is open, gh commands work without the YubiKey being touched again.
			The session ends when its time is up, when you run %[1]sgh auth lock%[1]s, or when the
			YubiKey is unplugged. Ending a session revokes its access token with GitHub, so a copy
			of the token taken while the session was open stops working too.

			A session cannot outlast the access token GitHub issues, so a long %[1]s--for%[1]s may be
			shortened.
		`, "`"),
		Example: heredoc.Doc(`
			# Unlock for the default hour
			$ gh auth unlock

			# Unlock for 15 minutes
			$ gh auth unlock --for 15m
		`),
		RunE: func(cmd *cobra.Command, args []string) error {
			return unlockRun(opts)
		},
	}
	cmd.Flags().StringVarP(&opts.Hostname, "hostname", "h", "", "The hostname of the GitHub instance to unlock")
	cmd.Flags().DurationVar(&opts.For, "for", yubikey.DefaultSessionTTL, "How long the session lasts, such as 30m or 2h")
	return cmd
}

func unlockRun(opts *unlockOptions) error {
	if opts.For < time.Minute {
		return cmdutil.FlagErrorf("`--for` must be at least 1m")
	}
	cfg, err := opts.Config()
	if err != nil {
		return err
	}
	authCfg := cfg.Authentication()
	cs := opts.IO.ColorScheme()

	hostname := opts.Hostname
	if hostname == "" {
		hostname, _ = authCfg.DefaultHost()
	}
	if !slices.Contains(authCfg.Hosts(), hostname) {
		return fmt.Errorf("not logged in to %s; run `gh auth login`", hostname)
	}
	username, err := authCfg.ActiveUser(hostname)
	if err != nil || username == "" {
		return fmt.Errorf("no active account for %s; run `gh auth login`", hostname)
	}
	vault, err := yubikey.LoadVault(hostname, username)
	if errors.Is(err, yubikey.ErrNoVault) {
		return fmt.Errorf("no YubiKey-protected credential for %s account %s; run `gh auth login`", hostname, username)
	}
	if err != nil {
		return err
	}
	recipient, err := vault.RecipientKey()
	if err != nil {
		return fmt.Errorf("corrupted vault: %w", err)
	}

	// Fail on a missing or wrong YubiKey before asking for the PIN.
	present, err := yubikey.ReadRecipient()
	if err != nil {
		return err
	}
	if !present.Equal(recipient) {
		return yubikey.ErrWrongDevice
	}

	// Unlocking spends the stored refresh token before the replacement can be stored, so make sure storing will work.
	if err := yubikey.CheckVaultWritable(); err != nil {
		return err
	}

	// Ask for the PIN before taking the lock, so the lock is not held while someone is typing.
	pin, err := promptPIN(opts.IO, opts.Prompter)
	if err != nil {
		return err
	}

	// End any session already open for this host, whichever account it belongs to. Its agent revokes its token and
	// stores the rotated credential, which is why this comes before the vault is read. The agent takes the credential
	// lock to do so, so this comes before this process takes it. If nothing genuine is listening, there is nothing to
	// end.
	for _, e := range (yubikey.Client{}).Lock(hostname) {
		if !e.Revoked {
			fmt.Fprintf(opts.IO.ErrOut, "%s The previous session's access token could not be revoked: %s\n", cs.WarningIcon(), e.RevokeError)
		}
	}

	// Hold the lock that login, logout and agents ending a session hold. The refresh token is single use, so two
	// unlocks must not both spend it, and an unlock must not put back a credential that a concurrent logout removed or
	// a login replaced.
	release, err := takeCredentialLock(time.Minute)
	if err != nil {
		return err
	}
	defer release()

	// Read the vault now that the lock is held: it may have been rotated, replaced or removed meanwhile.
	vault, err = yubikey.LoadVault(hostname, username)
	if errors.Is(err, yubikey.ErrNoVault) {
		return fmt.Errorf("%s account %s was logged out; run `gh auth login`", hostname, username)
	}
	if err != nil {
		return err
	}
	if recipient, err = vault.RecipientKey(); err != nil {
		return fmt.Errorf("corrupted vault: %w", err)
	}

	secret, err := yubikey.Unseal(vault, pin, func() {
		fmt.Fprintf(opts.IO.ErrOut, "%s Touch your YubiKey...\n", cs.Yellow("!"))
	})
	if err != nil {
		return err
	}

	// Bound every request: the credential lock is held, and other gh processes give up waiting for it after a minute.
	httpClient := yubikey.CredentialHTTPClient(30 * time.Second)
	renewed, err := authflow.NewTokenRefresher(httpClient).Refresh(secret.RefreshToken, hostname)
	if errors.Is(err, gh.ErrRefreshTokenInvalid) {
		return fmt.Errorf("GitHub rejected the stored credential for %s account %s (expired or revoked); run `gh auth login`", hostname, username)
	}
	if err != nil {
		return fmt.Errorf("could not get an access token: %w", err)
	}
	if renewed.AccessToken == "" || renewed.RefreshToken == "" {
		return errors.New("GitHub did not return a complete credential")
	}

	// The old refresh token is spent, so the new one must be sealed before anything else can fail.
	vaultID, err := yubikey.SealVault(hostname, username, recipient, yubikey.Secret{RefreshToken: renewed.RefreshToken}, renewed.RefreshTokenExpiresAt)
	if err != nil {
		return fmt.Errorf("could not store the renewed credential, so it is lost; run `gh auth login` to sign in again: %w", err)
	}
	session := yubikey.Session{Hostname: hostname, Username: username, Token: renewed.AccessToken, TokenExpiresAt: renewed.ExpiresAt}
	renewal := yubikey.Renewal{RefreshToken: renewed.RefreshToken, Recipient: recipient.Bytes(), VaultID: vaultID}

	// From here on a live access token exists. If the session cannot be opened after all, revoke it now: no agent
	// will be there to do it later. This process holds the credential lock, so it rotates directly.
	abandon := func(cause error) error {
		if err := rotate(httpClient, session, renewal); err != nil {
			return fmt.Errorf("%w\nThe access token issued for this attempt could not be revoked (%v); it expires on its own", cause, err)
		}
		return cause
	}

	// Anyone can seal a credential to the YubiKey's public key, so a vault file is no proof of whose credential it
	// holds. Ask the server which account the token belongs to before serving it as this account's.
	login, err := yubikey.TokenOwner(httpClient, hostname, renewed.AccessToken)
	if err != nil {
		return abandon(fmt.Errorf("could not confirm which account the credential belongs to, so the session was not opened: %w", err))
	}
	if !strings.EqualFold(login, username) {
		return abandon(fmt.Errorf("the stored credential belongs to %s, not %s, so the session was not opened; run `gh auth login`", login, username))
	}

	now := time.Now()
	deadline := now.Add(opts.For)
	shortened := false
	if renewed.ExpiresAt != nil && renewed.ExpiresAt.Before(deadline) {
		deadline = *renewed.ExpiresAt
		shortened = true
	}

	// The agent gets the refresh token as well: spending it is how the access token is revoked when the session
	// ends. It is the same token that was just sealed into the vault.
	session.Deadline = deadline
	if err := yubikey.StartAgent(yubikey.Handoff{Session: session, Renewal: renewal}, "auth", "agent"); err != nil {
		return abandon(fmt.Errorf("could not start the session: %w", err))
	}

	fmt.Fprintf(opts.IO.ErrOut, "%s Unlocked %s account %s until %s (%s)\n", cs.SuccessIcon(), hostname, cs.Bold(username),
		deadline.Local().Format("15:04"), remaining(deadline, now))
	if shortened {
		fmt.Fprintf(opts.IO.ErrOut, "%s Shorter than requested: GitHub's access token expires then\n", cs.WarningIcon())
	}
	return nil
}

// takeCredentialLock takes the cross-process lock that serializes every change to stored credentials.
func takeCredentialLock(wait time.Duration) (release func(), err error) {
	lockPath := config.CredentialLockPath()
	if err := os.MkdirAll(filepath.Dir(lockPath), 0o771); err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), wait)
	defer cancel()
	_, release, err = flock.Lock(ctx, lockPath)
	if err != nil {
		return nil, fmt.Errorf("another gh process is changing credentials: %w", err)
	}
	return release, nil
}

func remaining(deadline, now time.Time) string {
	left := deadline.Sub(now).Round(time.Minute)
	if left < time.Minute {
		return "less than a minute"
	}
	return text.Pluralize(int(left/time.Minute), "minute")
}

// NewCmdLock creates `gh auth lock`.
func NewCmdLock(f *cmdutil.Factory) *cobra.Command {
	var hostname string
	cmd := &cobra.Command{
		Use:   "lock",
		Args:  cobra.ExactArgs(0),
		Short: "End the unlocked session now",
		Long: heredoc.Docf(`
			End unlocked sessions immediately and revoke their access tokens with GitHub.

			Revoking needs the network. If GitHub cannot be reached, the session still ends, but a
			copy of its token taken earlier keeps working until the token expires.

			Without %[1]s--hostname%[1]s, every unlocked host is locked.
		`, "`"),
		RunE: func(cmd *cobra.Command, args []string) error {
			io := f.IOStreams
			cs := io.ColorScheme()
			ended := yubikey.Client{}.Lock(hostname)
			if len(ended) == 0 {
				fmt.Fprintf(io.ErrOut, "%s Already locked\n", cs.SuccessIcon())
				return nil
			}
			for _, e := range ended {
				if e.Revoked {
					fmt.Fprintf(io.ErrOut, "%s Locked %s account %s and revoked its access token\n",
						cs.SuccessIcon(), e.Hostname, cs.Bold(e.Username))
					continue
				}
				until := "it expires"
				if e.TokenExpiresAt != nil {
					until = e.TokenExpiresAt.Local().Format("15:04")
				}
				account := e.Hostname
				if e.Username != "" {
					account += " account " + cs.Bold(e.Username)
				}
				fmt.Fprintf(io.ErrOut, "%s Asked to lock %s, but its access token was not confirmed revoked: %s\n",
					cs.WarningIcon(), account, e.RevokeError)
				fmt.Fprintf(io.ErrOut, "  A copy of the token would work until %s\n", until)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&hostname, "hostname", "h", "", "Lock only this GitHub instance")
	return cmd
}

// NewCmdAgent creates the hidden `gh auth agent`, the background process `gh auth unlock` starts. It reads its session
// from standard input and prints one line on standard output: yubikey.AgentReady, or why it could not start.
func NewCmdAgent(f *cmdutil.Factory) *cobra.Command {
	return &cobra.Command{
		Use:    "agent",
		Args:   cobra.ExactArgs(0),
		Hidden: true,
		Short:  "Run the session agent (started by `gh auth unlock`)",
		RunE: func(cmd *cobra.Command, args []string) error {
			err := runAgent(f)
			if err != nil {
				// The parent is waiting for a line; tell it what went wrong.
				fmt.Fprintln(os.Stdout, strings.ReplaceAll(err.Error(), "\n", " "))
			}
			return err
		},
	}
}

func runAgent(f *cmdutil.Factory) error {
	var handoff yubikey.Handoff
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 1<<20)).Decode(&handoff); err != nil {
		return errors.New("no session was handed over; this command is started by `gh auth unlock`")
	}
	if err := handoff.Validate(time.Now()); err != nil {
		return err
	}

	// A stalled request must not keep a finished session's tokens in memory indefinitely.
	httpClient := yubikey.CredentialHTTPClient(20 * time.Second)

	listener, err := yubikey.Listen("", handoff.Session.Hostname)
	if err != nil {
		return err
	}

	// Tell the parent the session is being served, then let go of its pipe.
	fmt.Fprintln(os.Stdout, yubikey.AgentReady)
	os.Stdout.Close()

	agent := &yubikey.Agent{
		Revoke:     revokeByRotation(httpClient),
		KeyPresent: yubikey.KeyPresent,
		Logf:       fileLogger(yubikey.LogPath()),
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	return agent.Serve(ctx, listener, handoff)
}

// revokeByRotation returns the agent's way of revoking a session's access token: take the credential lock, then
// rotate. The lock makes the vault check and write inside rotate one step as far as sign-in, sign-out and unlock are
// concerned, since all of them hold the same lock while they change the vault.
func revokeByRotation(httpClient *http.Client) yubikey.RevokeFunc {
	return func(s yubikey.Session, r yubikey.Renewal) error {
		release, err := takeCredentialLock(time.Minute)
		if err != nil {
			return err
		}
		defer release()
		return rotate(httpClient, s, r)
	}
}

// rotate revokes a session's access token: it spends the session's refresh token, which makes GitHub invalidate the
// access token issued with it, seals the replacement refresh token into the vault, and drops the replacement access
// token without ever using it. The caller must hold the credential lock.
func rotate(httpClient *http.Client, s yubikey.Session, r yubikey.Renewal) error {
	recipient, err := ecdh.P256().NewPublicKey(r.Recipient)
	if err != nil {
		return fmt.Errorf("invalid sealing key: %w", err)
	}
	// Spending the refresh token before knowing the replacement can be stored would lose the sign-in.
	if err := yubikey.CheckVaultWritable(); err != nil {
		return err
	}

	renewed, err := authflow.NewTokenRefresher(httpClient).Refresh(r.RefreshToken, s.Hostname)
	if errors.Is(err, gh.ErrRefreshTokenInvalid) {
		// Someone else already spent this refresh token, which is what invalidates the access token. That is
		// normally a newer unlock of the same account. It cannot be confirmed from here, so it is reported.
		return errors.New("the session's refresh token was already used elsewhere, which should have revoked the token")
	}
	if err != nil {
		return fmt.Errorf("could not reach %s: %w", s.Hostname, err)
	}
	if renewed.RefreshToken == "" {
		return errors.New("the token was revoked, but the server returned no new credential; run `gh auth login`")
	}

	// The access token is dead now. Keep the sign-in alive by storing the replacement refresh token, but only if the
	// vault is still the one this session came from. If the account was signed out, or signed in again, in the
	// meantime, the vault is no longer this session's to replace, and the replacement is dropped. A vault that cannot
	// be read is a different matter: that is retried, and reported if it persists, because dropping the replacement
	// then would lose the sign-in.
	var current string
	for attempt := 0; ; attempt++ {
		current, err = yubikey.VaultID(s.Hostname, s.Username)
		if err == nil || errors.Is(err, yubikey.ErrNoVault) || attempt == 3 {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if errors.Is(err, yubikey.ErrNoVault) || (err == nil && current != r.VaultID) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("the token was revoked, but the stored sign-in could not be read to renew it; run `gh auth login`: %w", err)
	}
	_, err = yubikey.SealVault(s.Hostname, s.Username, recipient, yubikey.Secret{RefreshToken: renewed.RefreshToken}, renewed.RefreshTokenExpiresAt)
	if err != nil {
		return fmt.Errorf("the token was revoked, but the renewed sign-in could not be stored; run `gh auth login`: %w", err)
	}
	return nil
}

func fileLogger(path string) func(string, ...any) {
	return func(format string, args ...any) {
		f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
		if err != nil {
			return
		}
		defer f.Close()
		fmt.Fprintf(f, "%s %s\n", time.Now().Format(time.RFC3339), fmt.Sprintf(format, args...))
	}
}

// PrintStatus is `gh auth status` under the YubiKey gate: which accounts exist and whether each is unlocked. It
// returns cmdutil.SilentError when nothing is logged in, like the stock command.
func PrintStatus(io *iostreams.IOStreams, authCfg gh.AuthConfig, onlyHost string) error {
	cs := io.ColorScheme()
	// A host with no accounts is only known from the environment, which this build does not take credentials from.
	hosts := slices.DeleteFunc(slices.Clone(authCfg.Hosts()), func(host string) bool {
		return len(authCfg.UsersForHost(host)) == 0
	})
	if len(hosts) == 0 {
		fmt.Fprintf(io.ErrOut, "You are not logged into any GitHub hosts. To log in, run: %s\n", cs.Bold("gh auth login"))
		return cmdutil.SilentError
	}
	if onlyHost != "" && !slices.Contains(hosts, onlyHost) {
		fmt.Fprintf(io.ErrOut, "You are not logged into any accounts on %s\n", onlyHost)
		return cmdutil.SilentError
	}

	sessions := map[string]yubikey.Session{}
	for _, s := range (yubikey.Client{}).Sessions() {
		sessions[s.Hostname] = s
	}
	now := time.Now()

	for _, host := range hosts {
		if onlyHost != "" && host != onlyHost {
			continue
		}
		fmt.Fprintln(io.Out, cs.Bold(host))
		active, _ := authCfg.ActiveUser(host)
		for _, user := range authCfg.UsersForHost(host) {
			vault, err := yubikey.LoadVault(host, user)
			switch {
			case err != nil:
				fmt.Fprintf(io.Out, "  %s %s: no usable YubiKey-protected credential (%v); run %s\n",
					cs.FailureIcon(), cs.Bold(user), err, cs.Bold("gh auth login"))
				continue
			case user != active:
				fmt.Fprintf(io.Out, "  - %s: inactive account\n", cs.Bold(user))
			default:
				if s, ok := sessions[host]; ok && s.Username == user && now.Before(s.Deadline) {
					fmt.Fprintf(io.Out, "  %s %s: unlocked until %s (%s left)\n", cs.SuccessIcon(), cs.Bold(user),
						s.Deadline.Local().Format("15:04"), remaining(s.Deadline, now))
				} else {
					fmt.Fprintf(io.Out, "  %s %s: locked; run %s\n", cs.Yellow("!"), cs.Bold(user), cs.Bold("gh auth unlock"))
				}
			}
			line := "    - Credential sealed to YubiKey key "
			if key, err := vault.RecipientKey(); err == nil {
				line += yubikey.Fingerprint(key)
			} else {
				line += "(unreadable)"
			}
			line += fmt.Sprintf(" (PIV slot %x)", yubikey.SlotKey)
			if vault.RefreshTokenExpiresAt != nil {
				line += ", sign-in valid until " + vault.RefreshTokenExpiresAt.Local().Format("2006-01-02")
			}
			fmt.Fprintln(io.Out, line)
		}
	}
	return nil
}
