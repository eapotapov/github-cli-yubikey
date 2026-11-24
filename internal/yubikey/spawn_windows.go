//go:build windows

package yubikey

// AgentReady is the line an agent prints on standard output once it is serving its session.
const AgentReady = "ready"

func StartAgent(h Handoff, agentArgs ...string) error { return errUnsupported }
