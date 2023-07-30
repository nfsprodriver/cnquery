//go:build linux || darwin || netbsd || openbsd || freebsd
// +build linux darwin netbsd openbsd freebsd

package windows

import "go.mondoo.com/cnquery/providers/os/connection/shared"

func GetWindowsOSBuild(conn shared.Connection) (*WindowsCurrentVersion, error) {
	return powershellGetWindowsOSBuild(conn)
}