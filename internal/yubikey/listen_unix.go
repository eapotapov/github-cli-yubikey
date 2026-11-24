//go:build !windows

package yubikey

import (
	"net"
	"syscall"
)

// listenPrivate creates the socket with a umask that denies group and others, so it is private from the moment it
// exists. The umask is process-wide; this is called once, at agent startup, before anything else creates files.
func listenPrivate(path string) (net.Listener, error) {
	old := syscall.Umask(0o077)
	defer syscall.Umask(old)
	return net.Listen("unix", path)
}
