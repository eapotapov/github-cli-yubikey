# gh with a YubiKey

A fork of the GitHub CLI that talks to GitHub only through a session opened with a YubiKey. Stock `gh` puts its token in the macOS keychain, where any program running as you can read it with `security find-generic-password -s gh:github.com -w`. This fork keeps only a refresh token on disk, encrypted to a key inside the YubiKey. Decrypting it takes the PIN and a touch.

It runs on macOS and needs a cgo build.

## Quick start

```
gh auth setup-yubikey     # once per YubiKey: creates a key in PIV slot 83
gh auth login             # sign in with a browser
gh auth unlock            # PIN and touch, opens a one-hour session
gh pr list                # normal use, the key is not touched again
gh auth lock              # close the session and revoke its token
```

## Commands

| Command | What it does |
|---|---|
| `gh auth setup-yubikey` | Generates a key in slot `83`. If the slot already holds one, prints its fingerprint and changes nothing. |
| `gh auth login` | Signs in with a browser. The YubiKey must be plugged in; no PIN is needed. `gh` stays locked afterwards. |
| `gh auth unlock [--for 30m] [-h host]` | Opens a session. One hour by default, one minute at least. |
| `gh auth lock [-h host]` | Closes the session and revokes its token. Without `-h`, closes all of them. |
| `gh auth status` | Shows, per account, whether a session is open and how long it has left. |
| `gh auth logout` | Closes the session, deletes the encrypted token and the host entry. |
| `gh auth token` | Prints the token of the open session. Extensions and git need it. |

With no open session, any command that needs GitHub prints `gh is locked` and exits with code 4.

## How it works

### The key

`gh auth setup-yubikey` asks the YubiKey to generate a P-256 key pair in slot `83`, the second of the PIV "retired" slots, which in practice are general-purpose slots. The private half is created on the device and cannot be exported. The key requires the PIN once per connection and a touch for every operation.

Each time it uses the key, `gh` checks that the key was generated on the device and not imported, and that both policies are on. A key with a cached touch policy is rejected, because a second `unlock` within a few seconds would then go through untouched.

Generating a key needs the management key. `gh` reads it from the YubiKey's PIN-protected storage, the mode set up by `ykman piv access change-management-key --protect`. If the management key is not stored there, the command prints the `ykman` invocation to create the key by hand.

Code: [`internal/yubikey/device_darwin.go`](internal/yubikey/device_darwin.go), functions `GenerateKey` and `slotKey`.

### Encrypting the token

The scheme is the one `age-plugin-yubikey` uses:

1. `gh` creates a one-time P-256 key pair and runs ECDH against the YubiKey's public key.
2. HKDF-SHA256 derives 32 bytes from the shared secret. The salt contains both public keys, and `info` is the string `gh-yubikey-vault/v1`.
3. The token is encrypted with AES-256-GCM. The hostname and account name are passed as additional authenticated data, so one account's file will not decrypt as another's.

Encrypting needs only the public key, so it takes no PIN and no touch. Decrypting needs the private key to run the ECDH, and only the YubiKey has it. Token revocation, described below, depends on this difference.

Code: [`internal/yubikey/seal.go`](internal/yubikey/seal.go) (`Seal`, `Open`) and [`internal/yubikey/vault.go`](internal/yubikey/vault.go) (`SealVault`, `LoadVault`, `OpenSecret`).

### Signing in

`gh auth login` and `gh auth logout` end an open session for the host before they change the stored credential, and check again afterwards for a session started in the meantime.

`gh auth login` always asks GitHub for an expiring token. GitHub issues an access token valid for 8 hours and a refresh token valid for about six months. The refresh token is encrypted and written to a file; the access token is discarded once sign-in finishes. Signing in with a pasted token (`--with-token`) is disabled: such a token has no refresh token, so there would be nothing to encrypt.

Sign-in also removes any plaintext tokens for the account from `hosts.yml`. The fork neither reads nor cleans the macOS keychain.

Code: [`internal/config/yubikey.go`](internal/config/yubikey.go), function `gatedLoginRefreshable`.

### Opening a session

`gh auth unlock` does this:

1. Compares the plugged-in YubiKey's public key with the one the file is encrypted to. A different key is rejected before the PIN prompt.
2. Checks that the directory holding the file is writable, by writing and syncing a file of about the same size.
3. Asks for the PIN.
4. Ends any session already open for the host, so its token is revoked and its rotated refresh token is in the file before the file is read.
5. Takes the lock it shares with `login`, `logout`, and agents that are ending a session.
6. The YubiKey verifies the PIN, waits for a touch, and runs the ECDH. `gh` decrypts the refresh token.
7. `gh` exchanges the refresh token with GitHub for a new pair. Refresh tokens are single-use, so the old one stops working here.
8. The new refresh token is encrypted and atomically replaces the file.
9. `gh` asks GitHub which account the new access token belongs to. If it is not the account being unlocked, or GitHub cannot be asked, `gh` revokes the new token and stops.
10. `gh` starts the agent and hands it the access token and the refresh token.

Step 2 comes before step 7 because spending the refresh token and then failing to store its replacement loses the sign-in, and only `gh auth login` gets it back. The write in step 8 is retried a few times for the same reason.

Step 9 is there because the file says nothing about who wrote it. Encrypting needs only the public key, so any program could write a file holding the refresh token of a different account. Without the check, `gh` would act as that account while showing yours.

Steps 7 and 9 do not use `gh`'s usual HTTP client. That client follows `gh`'s configuration, where `http_unix_socket` sends every request to a local socket without TLS and `api_host` sends API requests to another server. It also uses a proxy named in the environment, and Go trusts a certificate bundle named in `SSL_CERT_FILE`, so the two together can read TLS traffic. A program able to edit the config file or the environment could use these to read a refresh token in transit or to forge the answer in step 9. These requests ignore `gh`'s configuration, use no proxy, and connect straight to the host's own address. The agent's exchange at the end of a session and the browser sign-in do the same. They do not work from behind a mandatory HTTP proxy.

Code: [`internal/yubikey/http.go`](internal/yubikey/http.go) (`CredentialHTTPClient`, `TokenOwner`).

A session cannot outlast its access token. `gh auth unlock --for 24h` opens an 8-hour session and says so.

Code: [`pkg/cmd/auth/yubikey/yubikey.go`](pkg/cmd/auth/yubikey/yubikey.go) (`unlockRun`) and [`internal/yubikey/device_darwin.go`](internal/yubikey/device_darwin.go) (`Unseal`).

### The agent

A background process, `gh auth agent`, holds the session's tokens in memory. There is one agent per unlocked host, and it exits when its session ends.

`unlock` starts the agent as its own child process and writes the tokens to the child's standard input. That pipe exists only between the two processes. The tokens are not sent over a socket, because a socket has a path, and there is no way to tell whether the process listening on a path is the agent or a program that got there first.

After that the agent listens on a unix socket, and other `gh` commands use it. The socket accepts three requests: return the access token, report the session's status, end the session. No request installs or changes a session, and no reply contains the refresh token.

Once a second the agent checks whether the session has reached its deadline and whether a YubiKey is still plugged in. The deadline is compared against wall-clock time, so a sleeping laptop does not extend a session. The session closes after two consecutive checks with no YubiKey, about two seconds after the key is pulled.

The socket is created with mode `600` inside a directory with mode `700`. A new agent replaces whatever is at its socket path, and an exiting agent removes the socket file only if it is still its own.

Code: [`internal/yubikey/agent.go`](internal/yubikey/agent.go) (`Agent`, `Client`, `Listen`, `Handoff`) and [`internal/yubikey/spawn_unix.go`](internal/yubikey/spawn_unix.go) (`StartAgent`).

### Closing a session and revoking the token

A session closes on `gh auth lock`, on its deadline, when the YubiKey is unplugged, and when the agent is stopped by a signal. In every case the agent first stops handing out the token, then revokes it. It does this once: a `gh auth lock` that arrives while the agent is already revoking waits and reports the outcome of that attempt.

GitHub has a request for revoking a token (`DELETE /applications/{client_id}/token`), but it revokes the paired refresh token as well. Using it would mean a browser sign-in after every session. Revocation is done by exchange instead:

1. The agent exchanges the session's refresh token for a new pair. GitHub stops accepting the previous access token at that moment.
2. The new refresh token is encrypted to the YubiKey's public key and replaces the file. No touch is needed. The agent only replaces the file its session came from: if you signed out or signed in again meanwhile, it leaves the file alone and drops the new token.
3. The agent discards the new access token without showing it to anyone.

Both facts about GitHub's behavior were checked on a live account: after `lock` and after pulling the key, a saved copy of the token got `401`, and the next `unlock` succeeded.

If GitHub cannot be reached, the session still closes, but the token stays valid until it expires. `gh auth lock` then prints the reason and the time until which the token still works.

Code: [`pkg/cmd/auth/yubikey/yubikey.go`](pkg/cmd/auth/yubikey/yubikey.go), function `revokeByRotation`.

### Where it is switched on

[`cmd/gh/main.go`](cmd/gh/main.go) calls `yubikey.Enable()`. No flag, environment variable, or setting turns it off. Tests do not call it, so the upstream tests pass unchanged.

With the mode on, [`internal/config/config.go`](internal/config/config.go) takes tokens from the agent only. The keychain, `hosts.yml`, and environment variables are not read.

## Differences from stock gh

- `GH_TOKEN`, `GITHUB_TOKEN`, and their enterprise variants are ignored. They are also removed from the environment of `gh` extensions and of `gh copilot`.
- `gh auth login` and `gh auth logout` fail if they cannot take the credential lock within a minute. Stock `gh` carries on without it.
- `gh auth login --with-token` is rejected, and `--insecure-storage` has no effect.
- `gh auth login` does not offer to upload an SSH key. To add one, open a session and run `gh ssh-key add ~/.ssh/id_ed25519.pub`. The token needs the `admin:public_key` scope for that, which sign-in no longer requests; get it once with `gh auth refresh -s admin:public_key`, then `gh auth unlock` again.
- Tokens are not refreshed automatically. When a session ends, you need a new `unlock`.
- Git receives the session token marked `ephemeral`, so caching credential helpers do not store it. This needs git 2.46 or newer.
- Under `GH_DEBUG=api`, token-exchange requests are logged as a single line with the URL, without headers or bodies.
- `gh auth status` reports session state, not token details.

## What it does not protect against

While a session is open, a program running as you can get the access token from the agent the same way `gh` does. Once the session closes, that token stops working, and a new one cannot be obtained without the YubiKey.

During a session the agent holds the refresh token in memory. A program able to read another process's memory can take it and mint new tokens without the key until you sign in again.

A program running as you can listen on the agent's socket path in place of the agent. It receives no tokens that way, because nothing sends tokens to the socket. It can make `gh` look locked, it can answer `gh` with an access token of its own choosing, so that `gh` acts as a different account, and it can tell `gh auth lock` that a token was revoked when the real agent was never asked. The real agent still ends its session on the deadline or when the key is pulled.

A program that can edit `gh`'s config file can route ordinary API requests through itself with `http_unix_socket` or `api_host`, and so see the access token of an open session. It cannot see a refresh token that way.

If the disk fills up between the moment a refresh token is spent and the moment its replacement is written, the sign-in is lost and `gh auth login` is needed. `gh` checks for free space first and retries the write, which narrows the window without closing it.

`gh copilot` starts Copilot CLI, which has its own `COPILOT_GITHUB_TOKEN` variable. `gh` does not remove it, so Copilot CLI can run with that token while `gh` is locked.

The agent checks that some YubiKey is plugged in, not the one that opened the session. With two keys plugged in, pulling one does not close the session. Checking the exact key would mean holding a connection to it the whole time, which would get in the way of SSH and other programs.

If the agent is killed with `kill -9`, or the machine loses power during a session, the token is not revoked and lives until it expires, at most 8 hours.

## When something goes wrong

`GitHub rejected the stored credential`. The saved refresh token is no longer accepted: it expired, you revoked the GitHub CLI app in your GitHub settings, or a token exchange was cut off midway. Run `gh auth login`.

`the stored credential belongs to X, not Y`. The encrypted file holds a token for a different account than the one being unlocked. Something other than `gh auth login` wrote that file. Run `gh auth login`, and treat it as a sign that a program on the machine is tampering with `gh`.

`another gh process is changing credentials`. Another `login`, `logout`, `unlock`, or session ending holds the lock. Wait for it and retry.

`this is not the YubiKey the credential is sealed to`. A different key is plugged in. Plug in the one you signed in with, or sign in again with this one.

`wrong PIN; N attempts left`. The PIN allows a limited number of attempts, usually three. A blocked PIN is reset with the PUK: `ykman piv access unblock-pin`.

`the YubiKey did not complete the operation`. The key was not touched in time. Run `unlock` again; the refresh token has not been spent at that point.

`could not open the YubiKey`. Another program is using the key. Wait a few seconds and retry.

Lost YubiKey. Revoke the GitHub CLI app in your GitHub settings (Settings → Applications → Authorized OAuth Apps). Then run `gh auth setup-yubikey` and `gh auth login` with the new key.

## Files

| Path | Contents |
|---|---|
| `~/.config/gh/yubikey/<host>__<user>.json` | The encrypted refresh token, the YubiKey's public key, and when the sign-in expires. No plaintext secrets. |
| `~/.config/gh/hosts.yml` | Hosts and accounts, without tokens. |
| `~/.local/state/gh/yubikey/agent-<host>.sock` | The socket of the agent for that host. |
| `~/.local/state/gh/yubikey/agent.log` | A log of when each session opened, when and why it closed, and whether its token was revoked. It contains no tokens. |
| `~/.local/state/gh/refresh.lock` | The lock taken by `login`, `logout`, `unlock`, and revocation. |

## Building and installing

```
make bin/gh
install -m 755 bin/gh /opt/homebrew/bin/gh
```

Homebrew does not update this copy, and `brew install gh` would replace it with the stock version.

To pull in upstream changes:

```
git fetch upstream
git merge upstream/trunk
```

## Checking that it works

The unit tests use a software key, so they do not exercise the YubiKey or GitHub. After building or updating, run these by hand with the key plugged in. `T` holds a copy of a session token so you can see whether GitHub still accepts it after the session is over.

Locking revokes the token, and the sign-in survives:

```
gh auth unlock --for 5m
gh api user --jq .login | cat
T=$(gh auth token)
gh auth lock
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: token $T" https://api.github.com/user
gh auth unlock --for 5m
```

`gh api` prints your login, `gh auth lock` reports `revoked its access token`, `curl` prints `401`, and the second `unlock` succeeds. If the second `unlock` says `GitHub rejected the stored credential`, revocation destroyed the sign-in.

Pulling the key does the same:

```
T=$(gh auth token)
```

Pull the YubiKey out, wait five seconds, plug it back in, then:

```
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: token $T" https://api.github.com/user
gh auth status
```

`curl` prints `401` and the account shows as `locked`.

Unlocking again ends the previous session, and the deadline ends a session without help:

```
gh auth unlock --for 5m
T=$(gh auth token)
gh auth unlock --for 1m
curl -s -o /dev/null -w "%{http_code}\n" -H "Authorization: token $T" https://api.github.com/user
sleep 75
gh auth status
unset T
```

`curl` prints `401` for the first session's token, and after the wait the account shows as `locked`.

The agent's log should have one `session started` line and one `session ended ... token revoked` line for each session, with the reasons `locked by user`, `YubiKey removed`, and `time limit reached`:

```
tail ~/.local/state/gh/yubikey/agent.log
```

A line ending in `token NOT revoked` gives the reason. That token works until it expires.

## Source map

| File | Contents |
|---|---|
| [`internal/yubikey/gate.go`](internal/yubikey/gate.go) | The on switch, paths, the slot number, the default session length. |
| [`internal/yubikey/seal.go`](internal/yubikey/seal.go) | ECDH, HKDF, AES-GCM. |
| [`internal/yubikey/vault.go`](internal/yubikey/vault.go) | The token file's format and its atomic write. |
| [`internal/yubikey/device_darwin.go`](internal/yubikey/device_darwin.go) | Talking to the YubiKey over PC/SC: finding it, checking policies, generating the key, decrypting. |
| [`internal/yubikey/agent.go`](internal/yubikey/agent.go) | The agent, the socket protocol, the client. |
| [`internal/yubikey/spawn_unix.go`](internal/yubikey/spawn_unix.go) | Starting the agent and handing it the session over a pipe. |
| [`internal/yubikey/env.go`](internal/yubikey/env.go) | Removing token variables from a child's environment. |
| [`internal/yubikey/http.go`](internal/yubikey/http.go) | The HTTP client for requests that carry credentials, and the account check. |
| [`internal/yubikey/yubikey_test.go`](internal/yubikey/yubikey_test.go), [`internal/yubikey/agent_test.go`](internal/yubikey/agent_test.go), [`internal/yubikey/http_test.go`](internal/yubikey/http_test.go) | Tests for encryption, the file, and the agent, with a software key standing in for the YubiKey. |
| [`internal/config/yubikey.go`](internal/config/yubikey.go) | Handing the token to commands; sign-in and sign-out in YubiKey mode. |
| [`pkg/cmd/auth/yubikey/yubikey.go`](pkg/cmd/auth/yubikey/yubikey.go) | The `setup-yubikey`, `unlock`, `lock`, and `agent` commands, the `status` output, token revocation. |
| [`pkg/cmd/root/root.go`](pkg/cmd/root/root.go) | The `gh is locked` message. |
| [`pkg/cmd/extension/manager.go`](pkg/cmd/extension/manager.go), [`pkg/cmd/copilot/copilot.go`](pkg/cmd/copilot/copilot.go) | Launching extensions and Copilot CLI without token variables. |
| [`pkg/cmd/auth/gitcredential/helper.go`](pkg/cmd/auth/gitcredential/helper.go) | The `ephemeral` mark for git. |
