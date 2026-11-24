//go:build darwin && cgo

package yubikey

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"errors"
	"fmt"
	"strings"

	"github.com/go-piv/piv-go/v2/piv"
)

func sealingSlot() piv.Slot {
	slot, ok := piv.RetiredKeyManagementSlot(SlotKey)
	if !ok {
		panic("invalid sealing slot")
	}
	return slot
}

func yubiKeyReaders() ([]string, error) {
	cards, err := piv.Cards()
	if err != nil {
		return nil, fmt.Errorf("could not list smart cards: %w", err)
	}
	var readers []string
	for _, card := range cards {
		if strings.Contains(strings.ToLower(card), "yubikey") {
			readers = append(readers, card)
		}
	}
	return readers, nil
}

// KeyPresent reports whether a YubiKey is plugged in. It only lists readers and never connects to the card, so it does
// not disturb other programs using the key.
func KeyPresent() (bool, error) {
	readers, err := yubiKeyReaders()
	return len(readers) > 0, err
}

// slotKey reads the sealing key's public half and checks it is one that can only be used with the hardware present:
// generated on the device, and requiring both the PIN and a touch.
func slotKey(yk *piv.YubiKey) (*ecdh.PublicKey, piv.KeyInfo, error) {
	info, err := yk.KeyInfo(sealingSlot())
	if err != nil {
		if errors.Is(err, piv.ErrNotFound) {
			return nil, info, ErrSlotEmpty
		}
		return nil, info, fmt.Errorf("could not read PIV slot %x: %w", SlotKey, err)
	}
	pub, ok := info.PublicKey.(*ecdsa.PublicKey)
	if !ok {
		return nil, info, fmt.Errorf("the key in PIV slot %x is not a P-256 key", SlotKey)
	}
	key, err := pub.ECDH()
	if err != nil || key.Curve() != ecdh.P256() {
		return nil, info, fmt.Errorf("the key in PIV slot %x is not a P-256 key", SlotKey)
	}
	if info.Origin != piv.OriginGenerated {
		return nil, info, fmt.Errorf("the key in PIV slot %x was imported, not generated on the YubiKey", SlotKey)
	}
	if info.PINPolicy == piv.PINPolicyNever {
		return nil, info, fmt.Errorf("the key in PIV slot %x does not require a PIN", SlotKey)
	}
	// A cached touch would let a second use within seconds go through untouched.
	if info.TouchPolicy != piv.TouchPolicyAlways {
		return nil, info, fmt.Errorf("the key in PIV slot %x does not require a touch for every use", SlotKey)
	}
	return key, info, nil
}

// withDevice runs fn against a plugged in YubiKey. When expected is set, it picks the YubiKey whose sealing key
// matches; otherwise the first one that has a usable sealing key, or failing that the first one that opens.
func withDevice(expected *ecdh.PublicKey, fn func(yk *piv.YubiKey, key *ecdh.PublicKey, info piv.KeyInfo, keyErr error) error) error {
	readers, err := yubiKeyReaders()
	if err != nil {
		return err
	}
	if len(readers) == 0 {
		return ErrNoDevice
	}

	var firstErr error
	for i, reader := range readers {
		yk, err := piv.Open(reader)
		if err != nil {
			if firstErr == nil {
				firstErr = fmt.Errorf("could not open the YubiKey (is another program using it?): %w", err)
			}
			continue
		}
		key, info, keyErr := slotKey(yk)
		last := i == len(readers)-1
		match := keyErr == nil && (expected == nil || key.Equal(expected))
		if !match && !last {
			yk.Close()
			continue
		}
		if keyErr == nil && expected != nil && !key.Equal(expected) {
			keyErr = ErrWrongDevice
		}
		err = fn(yk, key, info, keyErr)
		yk.Close()
		return err
	}
	return firstErr
}

// ReadRecipient returns the public key credentials are sealed to. It needs the YubiKey plugged in, but neither the PIN
// nor a touch.
func ReadRecipient() (*ecdh.PublicKey, error) {
	var recipient *ecdh.PublicKey
	err := withDevice(nil, func(_ *piv.YubiKey, key *ecdh.PublicKey, _ piv.KeyInfo, keyErr error) error {
		recipient = key
		return keyErr
	})
	return recipient, err
}

// Unseal reveals a vault's secret. The YubiKey checks the PIN and then waits for a touch; onTouch, if set, is called
// just before that wait so the caller can tell the person to touch the key.
func Unseal(v Vault, pin string, onTouch func()) (Secret, error) {
	expected, err := v.RecipientKey()
	if err != nil {
		return Secret{}, fmt.Errorf("corrupted vault: %w", err)
	}
	var secret Secret
	err = withDevice(expected, func(yk *piv.YubiKey, key *ecdh.PublicKey, info piv.KeyInfo, keyErr error) error {
		if keyErr != nil {
			return keyErr
		}
		// Check the PIN up front so a wrong one is reported before asking for a touch.
		if err := yk.VerifyPIN(pin); err != nil {
			return pinError(err)
		}
		priv, err := yk.PrivateKey(sealingSlot(), info.PublicKey, piv.KeyAuth{PIN: pin, PINPolicy: info.PINPolicy})
		if err != nil {
			return err
		}
		agreer, ok := priv.(*piv.ECDSAPrivateKey)
		if !ok {
			return errors.New("the YubiKey key does not support key agreement")
		}
		secret, err = v.OpenSecret(func(peer *ecdh.PublicKey) ([]byte, error) {
			if onTouch != nil {
				onTouch()
			}
			shared, err := agreer.ECDH(peer)
			if err != nil {
				return nil, fmt.Errorf("the YubiKey did not complete the operation (was it touched in time?): %w", pinError(err))
			}
			return shared, nil
		})
		return err
	})
	return secret, err
}

// GenerateKey creates the sealing key on the YubiKey and returns its public half. The private half is generated on the
// device and cannot leave it. It refuses to replace an existing key. The PIN is used to read the PIN-protected
// management key, which the YubiKey requires for key generation.
func GenerateKey(pin string) (*ecdh.PublicKey, error) {
	var generated *ecdh.PublicKey
	err := withDevice(nil, func(yk *piv.YubiKey, _ *ecdh.PublicKey, _ piv.KeyInfo, keyErr error) error {
		if !errors.Is(keyErr, ErrSlotEmpty) {
			if keyErr == nil {
				return ErrSlotOccupied
			}
			// An unusable key is still a key; never overwrite it.
			return fmt.Errorf("%w: %w", ErrSlotOccupied, keyErr)
		}
		metadata, err := yk.Metadata(pin)
		if err != nil {
			return pinError(err)
		}
		if metadata.ManagementKey == nil {
			return fmt.Errorf("the YubiKey's management key is not PIN-protected, so gh cannot use it; generate the key with:\n"+
				"  ykman piv keys generate --algorithm ECCP256 --pin-policy ONCE --touch-policy ALWAYS %x -", SlotKey)
		}
		pub, err := yk.GenerateKey(*metadata.ManagementKey, sealingSlot(), piv.Key{
			Algorithm:   piv.AlgorithmEC256,
			PINPolicy:   piv.PINPolicyOnce,
			TouchPolicy: piv.TouchPolicyAlways,
		})
		if err != nil {
			return fmt.Errorf("could not generate the key: %w", err)
		}
		ecdsaPub, ok := pub.(*ecdsa.PublicKey)
		if !ok {
			return errors.New("the YubiKey returned an unexpected key type")
		}
		generated, err = ecdsaPub.ECDH()
		return err
	})
	return generated, err
}

func pinError(err error) error {
	var authErr piv.AuthErr
	if errors.As(err, &authErr) {
		return &PINError{Retries: authErr.Retries}
	}
	return err
}
