//go:build windows

package config

import "golang.org/x/sys/windows/registry"

// platformMachineID reads the Windows MachineGuid.
//
// Written at installation and stable for the life of the install. Read from
// the 64-bit view explicitly: a 32-bit process would otherwise be redirected
// to the WOW6432Node view, which does not carry this value, and the fallback
// to hostname would kick in for no good reason.
func platformMachineID() string {
	k, err := registry.OpenKey(registry.LOCAL_MACHINE,
		`SOFTWARE\Microsoft\Cryptography`, registry.QUERY_VALUE|registry.WOW64_64KEY)
	if err != nil {
		return ""
	}
	defer k.Close()
	v, _, err := k.GetStringValue("MachineGuid")
	if err != nil || v == "" {
		return ""
	}
	return "machine-guid:" + v
}
