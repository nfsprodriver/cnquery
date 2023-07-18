//go:build !windows
// +build !windows

package windows

import "errors"

// non-windows stubs
func GetNativeRegistryKeyItems(path string) ([]RegistryKeyItem, error) {
	return nil, errors.New("native registry key items not supported on non-windows platforms")
}

func GetNativeRegistryKeyChildren(path string) ([]RegistryKeyChild, error) {
	return nil, errors.New("native registry key children not supported on non-windows platforms")
}
