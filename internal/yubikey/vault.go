package yubikey

import (
	"crypto/ecdh"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net/url"
	"os"
	"path/filepath"
	"time"
)

// ErrNoVault reports that no sealed credential is stored for the account.
var ErrNoVault = errors.New("no YubiKey-protected credential stored")

// Secret is the part of a vault only the YubiKey can reveal.
type Secret struct {
	RefreshToken string `json:"refresh_token"`
}

// Vault is the on-disk record for one account. Everything outside Envelope is plaintext metadata, so it must stay free
// of secrets.
type Vault struct {
	Version  int    `json:"version"`
	Hostname string `json:"hostname"`
	Username string `json:"username"`
	// Recipient is the YubiKey's public key the envelope is sealed to, in uncompressed SEC 1 form.
	Recipient []byte `json:"recipient"`
	// RefreshTokenExpiresAt is when the sealed refresh token stops working, if the server said.
	RefreshTokenExpiresAt *time.Time `json:"refresh_token_expires_at,omitempty"`
	Envelope              Envelope   `json:"envelope"`
}

// RecipientKey parses the public key the vault is sealed to.
func (v Vault) RecipientKey() (*ecdh.PublicKey, error) {
	return ecdh.P256().NewPublicKey(v.Recipient)
}

// Fingerprint is a short, stable identifier for a sealing key, for showing to people.
func Fingerprint(key *ecdh.PublicKey) string {
	sum := sha256.Sum256(key.Bytes())
	return hex.EncodeToString(sum[:8])
}

func vaultAAD(hostname, username string) []byte {
	return []byte(sealInfo + "\x00" + hostname + "\x00" + username)
}

func vaultPath(hostname, username string) string {
	name := url.PathEscape(hostname) + "__" + url.PathEscape(username) + ".json"
	return filepath.Join(vaultDir(), name)
}

// SealVault seals secret to recipient and writes it as the account's vault, replacing any previous one atomically. It
// needs no access to the YubiKey's private key, so it can run without a PIN or a touch. It returns the identity of the
// file it wrote; see VaultID.
//
// The secret is usually a refresh token whose predecessor has just been spent, so a failed write loses the sign-in.
// The write is therefore retried a few times before giving up.
func SealVault(hostname, username string, recipient *ecdh.PublicKey, secret Secret, refreshTokenExpiresAt *time.Time) (string, error) {
	if hostname == "" || username == "" {
		return "", errors.New("hostname and username are required")
	}
	if secret.RefreshToken == "" {
		return "", errors.New("refresh token is required")
	}
	plaintext, err := json.Marshal(secret)
	if err != nil {
		return "", err
	}
	env, err := Seal(recipient, plaintext, vaultAAD(hostname, username))
	if err != nil {
		return "", err
	}
	v := Vault{
		Version:               1,
		Hostname:              hostname,
		Username:              username,
		Recipient:             recipient.Bytes(),
		RefreshTokenExpiresAt: refreshTokenExpiresAt,
		Envelope:              env,
	}
	data, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return "", err
	}
	for attempt := 0; ; attempt++ {
		err = writeFileAtomic(vaultPath(hostname, username), data)
		if err == nil || attempt == sealWriteRetries {
			break
		}
		time.Sleep(sealWriteRetryDelay)
	}
	if err != nil {
		return "", err
	}
	return vaultIdentity(data), nil
}

const sealWriteRetries = 3

var sealWriteRetryDelay = 300 * time.Millisecond

func vaultIdentity(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}

// VaultID identifies the exact vault file currently stored for the account. Every write produces a new identity,
// because sealing uses a fresh one-time key. An agent remembers the identity of the vault its session came from, and
// only replaces the vault at the end of the session if it is still that one, so it never overwrites a credential
// stored by a later sign-in.
func VaultID(hostname, username string) (string, error) {
	data, err := os.ReadFile(vaultPath(hostname, username))
	if errors.Is(err, fs.ErrNotExist) {
		return "", ErrNoVault
	}
	if err != nil {
		return "", err
	}
	return vaultIdentity(data), nil
}

// LoadVault reads the account's vault, returning ErrNoVault when there is none.
func LoadVault(hostname, username string) (Vault, error) {
	data, err := os.ReadFile(vaultPath(hostname, username))
	if errors.Is(err, fs.ErrNotExist) {
		return Vault{}, ErrNoVault
	}
	if err != nil {
		return Vault{}, err
	}
	var v Vault
	if err := json.Unmarshal(data, &v); err != nil {
		return Vault{}, fmt.Errorf("corrupted vault: %w", err)
	}
	if v.Version != 1 {
		return Vault{}, fmt.Errorf("unsupported vault version %d", v.Version)
	}
	if v.Hostname != hostname || v.Username != username {
		return Vault{}, errors.New("vault does not belong to this account")
	}
	return v, nil
}

// HasVault reports whether a vault is stored for the account.
func HasVault(hostname, username string) bool {
	_, err := os.Stat(vaultPath(hostname, username))
	return err == nil
}

// DeleteVault removes the account's vault. A missing vault is not an error.
func DeleteVault(hostname, username string) error {
	err := os.Remove(vaultPath(hostname, username))
	if errors.Is(err, fs.ErrNotExist) {
		return nil
	}
	return err
}

// OpenSecret unseals the vault's secret, using agree for the YubiKey's side of the key agreement.
func (v Vault) OpenSecret(agree ECDHFunc) (Secret, error) {
	recipient, err := v.RecipientKey()
	if err != nil {
		return Secret{}, fmt.Errorf("corrupted vault: %w", err)
	}
	plaintext, err := Open(v.Envelope, recipient, agree, vaultAAD(v.Hostname, v.Username))
	if err != nil {
		return Secret{}, err
	}
	var secret Secret
	if err := json.Unmarshal(plaintext, &secret); err != nil {
		return Secret{}, errors.New("corrupted vault contents")
	}
	if secret.RefreshToken == "" {
		return Secret{}, errors.New("corrupted vault contents")
	}
	return secret, nil
}

func writeFileAtomic(path string, data []byte) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, ".tmp-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		return err
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmp.Name(), path); err != nil {
		return err
	}
	// Sync the directory too, or a power loss could bring back the previous file, whose refresh token is spent.
	if d, err := os.Open(dir); err == nil {
		_ = d.Sync()
		d.Close()
	}
	return nil
}

// CheckVaultWritable verifies a vault can be written right now. Unlocking spends the stored refresh token before it
// can store the replacement, so a storage problem has to be caught beforehand.
func CheckVaultWritable() error {
	dir := vaultDir()
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("cannot write to %s: %w", dir, err)
	}
	probe, err := os.CreateTemp(dir, ".probe-*")
	if err != nil {
		return fmt.Errorf("cannot write to %s: %w", dir, err)
	}
	defer os.Remove(probe.Name())
	// Write and sync about as much as a vault takes, so a full disk or an exhausted quota shows up here.
	_, err = probe.Write(make([]byte, 4096))
	if err == nil {
		err = probe.Sync()
	}
	if cerr := probe.Close(); err == nil {
		err = cerr
	}
	if err != nil {
		return fmt.Errorf("cannot write to %s: %w", dir, err)
	}
	return nil
}
