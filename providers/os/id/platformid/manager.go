package platformid

import (
	"go.mondoo.com/cnquery/providers-sdk/v1/inventory"
	"go.mondoo.com/cnquery/providers/os/connection/shared"
)

type UniquePlatformIDProvider interface {
	Name() string
	ID() (string, error)
}

func MachineIDProvider(conn shared.Connection, platform *inventory.Platform) (UniquePlatformIDProvider, error) {
	var uuidProvider UniquePlatformIDProvider
	for i := range platform.Family {
		if platform.Family[i] == "linux" {
			uuidProvider = &LinuxIdProvider{connection: conn}
		}
	}

	if uuidProvider == nil && platform.Name == "macos" {
		uuidProvider = &MacOSIdProvider{connection: conn}
	} else if uuidProvider == nil && platform.Name == "windows" {
		uuidProvider = &WinIdProvider{connection: conn}
	}

	return uuidProvider, nil
}
