//go:build !windows && !linux

package service

import (
	"context"
	"os"
	"path/filepath"
)

// Platforms other than Windows and Linux are not shipping targets
// (ARCHITECTURE.md §10 names windows/amd64, linux/amd64, linux/arm64). The
// daemon still RUNS here -- `notifymatrix run` works fine on a developer's
// macOS machine -- it simply cannot install itself as a service.
//
// Refusing explicitly rather than stubbing a no-op installer: an install verb
// that silently succeeds and installs nothing is exactly the kind of quiet
// failure this product exists to avoid.

func defaultDataDir() string {
	if h, err := os.UserHomeDir(); err == nil {
		return filepath.Join(h, ".local", "state", Name)
	}
	return filepath.Join(os.TempDir(), Name)
}

func New() Manager { return unsupported{} }

type unsupported struct{}

func (unsupported) Install(InstallOptions) error { return ErrUnsupported }
func (unsupported) Uninstall() error             { return ErrUnsupported }
func (unsupported) Start() error                 { return ErrUnsupported }
func (unsupported) Stop() error                  { return ErrUnsupported }
func (unsupported) Status() (Status, error)      { return Status{State: StateNotInstalled}, nil }
func (unsupported) UnitText(InstallOptions) (string, error) {
	return "", ErrUnsupported
}

func RunAsService(func(context.Context) error) (bool, error) { return false, nil }

// EscapeArg is a no-op off Windows: nothing here builds a command line as
// a single string.
func EscapeArg(s string) string { return s }

func Elevate(string) error { return ErrUnsupported }
