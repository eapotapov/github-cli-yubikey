package yubikey

import (
	"errors"
	"fmt"
)

var (
	// ErrNoDevice reports that no YubiKey is plugged in.
	ErrNoDevice = errors.New("no YubiKey found; plug it in and try again")

	// ErrSlotEmpty reports that the YubiKey has no sealing key yet.
	ErrSlotEmpty = fmt.Errorf("the YubiKey has no key in PIV slot %x; run `gh auth setup-yubikey` first", SlotKey)

	// ErrWrongDevice reports that the plugged in YubiKey is not the one a vault is sealed to.
	ErrWrongDevice = errors.New("this is not the YubiKey the credential is sealed to")

	// ErrSlotOccupied reports that key generation would overwrite an existing key.
	ErrSlotOccupied = fmt.Errorf("PIV slot %x already holds a key", SlotKey)
)

// PINError reports a rejected PIN.
type PINError struct {
	// Retries is how many attempts remain before the PIN is blocked.
	Retries int
}

func (e *PINError) Error() string {
	if e.Retries == 0 {
		return "wrong PIN; the PIN is now blocked and must be reset with the PUK"
	}
	return fmt.Sprintf("wrong PIN; %d attempts left before it is blocked", e.Retries)
}
