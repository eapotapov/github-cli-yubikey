//go:build windows

package yubikey

import "net"

func listenPrivate(path string) (net.Listener, error) { return net.Listen("unix", path) }
