package yubikey

import (
	"slices"
	"strings"
)

// StripTokenEnv returns env without the variables gh and tools built on go-gh read a GitHub token from. Programs gh
// launches, such as extensions, take a token from the environment before they ask gh for one; removing these makes
// them go through gh, and so through an unlocked session.
func StripTokenEnv(env []string) []string {
	return slices.DeleteFunc(slices.Clone(env), func(kv string) bool {
		name, _, _ := strings.Cut(kv, "=")
		switch name {
		case "GH_TOKEN", "GITHUB_TOKEN", "GH_ENTERPRISE_TOKEN", "GITHUB_ENTERPRISE_TOKEN":
			return true
		}
		return false
	})
}
