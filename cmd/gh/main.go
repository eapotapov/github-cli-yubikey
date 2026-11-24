package main

import (
	"os"

	"github.com/cli/cli/v2/internal/ghcmd"
	"github.com/cli/cli/v2/internal/yubikey"
)

func main() {
	// This build only ever uses GitHub credentials through a YubiKey-gated session. There is deliberately no flag,
	// environment variable or config setting that turns the gate off.
	yubikey.Enable()
	code := ghcmd.Main()
	os.Exit(int(code))
}
