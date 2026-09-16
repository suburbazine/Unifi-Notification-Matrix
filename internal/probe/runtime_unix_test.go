//go:build !windows

package probe

// runtimeIsUnix gates the file-permission assertion. Windows does not have
// POSIX modes, and asserting 0600 there tests the Go runtime's emulation
// rather than this package.
func runtimeIsUnix() bool { return true }
