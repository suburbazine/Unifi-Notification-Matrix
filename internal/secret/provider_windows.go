//go:build windows

package secret

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

func init() {
	providers = []Provider{dpapiProvider{}, plainProvider{}}
}

// SetKeyFile is a no-op on Windows: the key-file tier exists only where there
// is no DPAPI. Declared here so callers configure the secret store without
// build tags of their own.
func SetKeyFile(string) {}

// dpapiProvider uses DPAPI at MACHINE scope: any account on this machine can
// decrypt, no other machine can.
//
// Machine scope rather than per-user is required because the Windows service
// account and the interactive operator must share one config -- the daemon runs
// as a service and is configured from a browser session running as the
// operator. Per-user scope would mean the service could not read what the
// operator just saved.
//
// Note that the Linux tiers are strictly TIGHTER than this (root or the tss
// group only). That asymmetry is deliberate and documented; it is not an
// oversight to be "fixed" by loosening Linux.
type dpapiProvider struct{}

func (dpapiProvider) Prefix() string    { return PrefixDPAPI }
func (dpapiProvider) Mechanism() string { return "Windows DPAPI (machine scope)" }

func (dpapiProvider) Available() (bool, string) { return true, "" }

func (dpapiProvider) MachineBound() bool { return true }

func newBlob(d []byte) *windows.DataBlob {
	if len(d) == 0 {
		return &windows.DataBlob{}
	}
	return &windows.DataBlob{Size: uint32(len(d)), Data: &d[0]}
}

func blobBytes(b *windows.DataBlob) []byte {
	if b.Size == 0 {
		return nil
	}
	out := make([]byte, b.Size)
	copy(out, unsafe.Slice(b.Data, b.Size))
	return out
}

func (dpapiProvider) Protect(plaintext []byte) ([]byte, error) {
	var out windows.DataBlob
	err := windows.CryptProtectData(newBlob(plaintext), nil, nil, 0, nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN|windows.CRYPTPROTECT_LOCAL_MACHINE, &out)
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return blobBytes(&out), nil
}

func (dpapiProvider) Unprotect(blob []byte) ([]byte, error) {
	var out windows.DataBlob
	// CRYPTPROTECT_UI_FORBIDDEN: a service has no desktop to prompt on, and a
	// blocked prompt would hang the daemon rather than fail it.
	err := windows.CryptUnprotectData(newBlob(blob), nil, nil, 0, nil,
		windows.CRYPTPROTECT_UI_FORBIDDEN, &out)
	if err != nil {
		return nil, err
	}
	defer windows.LocalFree(windows.Handle(unsafe.Pointer(out.Data)))
	return blobBytes(&out), nil
}
