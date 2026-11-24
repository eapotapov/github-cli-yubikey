//go:build !windows

package yubikey

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"syscall"
	"time"
)

// AgentReady is the line an agent prints on standard output once it is serving its session.
const AgentReady = "ready"

// StartAgent starts a background agent for the handed-off session. The agent is this same executable run with
// agentArgs, detached into its own session so it outlives the terminal that started it.
//
// The session, which includes the refresh token, is written to the agent's standard input: a pipe that exists only
// between this process and the one it just started. It is deliberately not sent over the agent's socket, because
// there is no way to know who is listening on a socket path. StartAgent returns once the agent reports it is serving.
func StartAgent(h Handoff, agentArgs ...string) error {
	payload, err := json.Marshal(h)
	if err != nil {
		return err
	}
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	cmd := exec.Command(exe, agentArgs...)
	cmd.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return err
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return err
	}
	if err := cmd.Start(); err != nil {
		return err
	}
	// Reap the agent if it exits while this process is still around; otherwise it runs on its own.
	exited := make(chan struct{})
	go func() {
		_ = cmd.Wait()
		close(exited)
	}()

	if _, err := stdin.Write(payload); err != nil {
		_ = cmd.Process.Kill()
		return fmt.Errorf("could not hand the session to the agent: %w", err)
	}
	stdin.Close()

	line := make(chan string, 1)
	go func() {
		text, _ := bufio.NewReader(stdout).ReadString('\n')
		line <- strings.TrimSpace(text)
	}()
	select {
	case text := <-line:
		if text == AgentReady {
			return nil
		}
		_ = cmd.Process.Kill()
		if text == "" {
			text = "it exited without reporting why"
		}
		return fmt.Errorf("the session agent did not start: %s", text)
	case <-time.After(15 * time.Second):
		_ = cmd.Process.Kill()
		return errors.New("the session agent did not start in time")
	}
}
