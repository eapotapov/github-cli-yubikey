//go:build !(darwin && cgo)

package yubikey

import (
	"crypto/ecdh"
	"errors"
)

var errUnsupported = errors.New("YubiKey support is only built for macOS with cgo enabled")

func KeyPresent() (bool, error) { return false, errUnsupported }

func ReadRecipient() (*ecdh.PublicKey, error) { return nil, errUnsupported }

func Unseal(Vault, string, func()) (Secret, error) { return Secret{}, errUnsupported }

func GenerateKey(string) (*ecdh.PublicKey, error) { return nil, errUnsupported }
