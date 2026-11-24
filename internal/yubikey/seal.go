package yubikey

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/hkdf"
	"crypto/rand"
	"crypto/sha256"
	"errors"
	"fmt"
)

// sealInfo binds derived keys to this format, so a shared secret can never be reused under another scheme.
const sealInfo = "gh-yubikey-vault/v1"

// Envelope is a secret sealed to a P-256 public key: ECDH against a one-time key, HKDF-SHA256, then AES-256-GCM.
// Nothing in it is secret. Sealing needs only the recipient's public key; opening needs the matching private key to
// redo the ECDH, which for a vault is an operation only the YubiKey can perform.
type Envelope struct {
	// Ephemeral is the one-time public key, in uncompressed SEC 1 form.
	Ephemeral []byte `json:"ephemeral"`
	Nonce     []byte `json:"nonce"`
	// Ciphertext includes the GCM tag.
	Ciphertext []byte `json:"ciphertext"`
}

// ECDHFunc performs the recipient's half of the key agreement with the given peer key.
type ECDHFunc func(peer *ecdh.PublicKey) ([]byte, error)

// Seal encrypts plaintext to recipient. aad is authenticated but not encrypted, and must be supplied again to Open.
func Seal(recipient *ecdh.PublicKey, plaintext, aad []byte) (Envelope, error) {
	if recipient.Curve() != ecdh.P256() {
		return Envelope{}, errors.New("recipient key must be P-256")
	}
	ephemeral, err := ecdh.P256().GenerateKey(rand.Reader)
	if err != nil {
		return Envelope{}, err
	}
	shared, err := ephemeral.ECDH(recipient)
	if err != nil {
		return Envelope{}, err
	}
	ephemeralPub := ephemeral.PublicKey().Bytes()
	aead, err := sealAEAD(shared, ephemeralPub, recipient.Bytes())
	if err != nil {
		return Envelope{}, err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return Envelope{}, err
	}
	return Envelope{
		Ephemeral:  ephemeralPub,
		Nonce:      nonce,
		Ciphertext: aead.Seal(nil, nonce, plaintext, aad),
	}, nil
}

// Open decrypts an envelope sealed to recipient, using agree to perform the recipient's side of the key agreement.
func Open(env Envelope, recipient *ecdh.PublicKey, agree ECDHFunc, aad []byte) ([]byte, error) {
	peer, err := ecdh.P256().NewPublicKey(env.Ephemeral)
	if err != nil {
		return nil, fmt.Errorf("invalid ephemeral key: %w", err)
	}
	shared, err := agree(peer)
	if err != nil {
		return nil, err
	}
	aead, err := sealAEAD(shared, env.Ephemeral, recipient.Bytes())
	if err != nil {
		return nil, err
	}
	if len(env.Nonce) != aead.NonceSize() {
		return nil, errors.New("invalid nonce")
	}
	plaintext, err := aead.Open(nil, env.Nonce, env.Ciphertext, aad)
	if err != nil {
		return nil, errors.New("could not decrypt: wrong key or corrupted data")
	}
	return plaintext, nil
}

func sealAEAD(shared, ephemeralPub, recipientPub []byte) (cipher.AEAD, error) {
	salt := append(append([]byte{}, ephemeralPub...), recipientPub...)
	key, err := hkdf.Key(sha256.New, shared, salt, sealInfo, 32)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}
