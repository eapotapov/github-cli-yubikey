package yubikey

import (
	"crypto/ecdh"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// softKey stands in for the YubiKey: a P-256 key whose private half is in memory.
func softKey(t *testing.T) (*ecdh.PrivateKey, ECDHFunc) {
	t.Helper()
	key, err := ecdh.P256().GenerateKey(rand.Reader)
	require.NoError(t, err)
	return key, func(peer *ecdh.PublicKey) ([]byte, error) { return key.ECDH(peer) }
}

func TestSealOpen(t *testing.T) {
	key, agree := softKey(t)
	aad := []byte("context")

	env, err := Seal(key.PublicKey(), []byte("secret"), aad)
	require.NoError(t, err)

	got, err := Open(env, key.PublicKey(), agree, aad)
	require.NoError(t, err)
	assert.Equal(t, "secret", string(got))

	t.Run("fresh ephemeral key and nonce every time", func(t *testing.T) {
		again, err := Seal(key.PublicKey(), []byte("secret"), aad)
		require.NoError(t, err)
		assert.NotEqual(t, env.Ephemeral, again.Ephemeral)
		assert.NotEqual(t, env.Ciphertext, again.Ciphertext)
	})

	t.Run("wrong key", func(t *testing.T) {
		_, otherAgree := softKey(t)
		_, err := Open(env, key.PublicKey(), otherAgree, aad)
		assert.Error(t, err)
	})

	t.Run("wrong associated data", func(t *testing.T) {
		_, err := Open(env, key.PublicKey(), agree, []byte("other"))
		assert.Error(t, err)
	})

	t.Run("tampered ciphertext", func(t *testing.T) {
		bad := env
		bad.Ciphertext = append([]byte{}, env.Ciphertext...)
		bad.Ciphertext[0] ^= 1
		_, err := Open(bad, key.PublicKey(), agree, aad)
		assert.Error(t, err)
	})

	t.Run("key agreement failure is surfaced", func(t *testing.T) {
		boom := errors.New("not touched")
		_, err := Open(env, key.PublicKey(), func(*ecdh.PublicKey) ([]byte, error) { return nil, boom }, aad)
		assert.ErrorIs(t, err, boom)
	})
}

func TestVault(t *testing.T) {
	t.Setenv("GH_CONFIG_DIR", t.TempDir())
	key, agree := softKey(t)
	expires := time.Date(2027, 5, 1, 0, 0, 0, 0, time.UTC)

	_, err := LoadVault("github.com", "monalisa")
	require.ErrorIs(t, err, ErrNoVault)
	assert.False(t, HasVault("github.com", "monalisa"))

	firstID, err := SealVault("github.com", "monalisa", key.PublicKey(), Secret{RefreshToken: "ghr_one"}, &expires)
	require.NoError(t, err)
	currentID, err := VaultID("github.com", "monalisa")
	require.NoError(t, err)
	assert.Equal(t, firstID, currentID)
	assert.True(t, HasVault("github.com", "monalisa"))

	v, err := LoadVault("github.com", "monalisa")
	require.NoError(t, err)
	require.NotNil(t, v.RefreshTokenExpiresAt)
	assert.True(t, expires.Equal(*v.RefreshTokenExpiresAt))
	recipient, err := v.RecipientKey()
	require.NoError(t, err)
	assert.True(t, recipient.Equal(key.PublicKey()))

	secret, err := v.OpenSecret(agree)
	require.NoError(t, err)
	assert.Equal(t, "ghr_one", secret.RefreshToken)

	t.Run("the file holds no plaintext token and is private", func(t *testing.T) {
		path := vaultPath("github.com", "monalisa")
		data, err := os.ReadFile(path)
		require.NoError(t, err)
		assert.NotContains(t, string(data), "ghr_one")
		info, err := os.Stat(path)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(0o600), info.Mode().Perm())
	})

	t.Run("a vault cannot be replayed under another account", func(t *testing.T) {
		data, err := os.ReadFile(vaultPath("github.com", "monalisa"))
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(vaultPath("github.com", "mallory"), data, 0o600))
		_, err = LoadVault("github.com", "mallory")
		assert.Error(t, err)

		// Even with the plaintext metadata rewritten to match, the sealed part is bound to the original account.
		moved := v
		moved.Username = "mallory"
		_, err = moved.OpenSecret(agree)
		assert.Error(t, err)
	})

	t.Run("resealing replaces the secret", func(t *testing.T) {
		secondID, err := SealVault("github.com", "monalisa", key.PublicKey(), Secret{RefreshToken: "ghr_two"}, nil)
		require.NoError(t, err)
		assert.NotEqual(t, firstID, secondID, "every write has its own identity")
		v, err := LoadVault("github.com", "monalisa")
		require.NoError(t, err)
		secret, err := v.OpenSecret(agree)
		require.NoError(t, err)
		assert.Equal(t, "ghr_two", secret.RefreshToken)
		assert.Nil(t, v.RefreshTokenExpiresAt)
	})

	t.Run("delete", func(t *testing.T) {
		require.NoError(t, DeleteVault("github.com", "monalisa"))
		require.NoError(t, DeleteVault("github.com", "monalisa"))
		assert.False(t, HasVault("github.com", "monalisa"))
		_, err := VaultID("github.com", "monalisa")
		assert.ErrorIs(t, err, ErrNoVault)
	})
}

func TestCheckVaultWritable(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GH_CONFIG_DIR", dir)
	require.NoError(t, CheckVaultWritable())

	require.NoError(t, os.Chmod(filepath.Join(dir, "yubikey"), 0o500))
	defer os.Chmod(filepath.Join(dir, "yubikey"), 0o700)
	assert.Error(t, CheckVaultWritable())
}

func TestStripTokenEnv(t *testing.T) {
	env := []string{"PATH=/bin", "GH_TOKEN=a", "GITHUB_TOKEN=b", "GH_ENTERPRISE_TOKEN=c", "GITHUB_ENTERPRISE_TOKEN=d", "GH_HOST=example.com", "GH_TOKEN_EXTRA=kept"}
	assert.Equal(t, []string{"PATH=/bin", "GH_HOST=example.com", "GH_TOKEN_EXTRA=kept"}, StripTokenEnv(env))
	assert.Len(t, env, 7, "the input is not modified")
}
