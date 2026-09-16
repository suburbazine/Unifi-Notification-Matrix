package config

import (
	"fmt"
	"os"
	"path/filepath"
)

// SetupTokenFile is the name of the file the one-time setup token is written
// to when one exists.
const SetupTokenFile = "setup-token.txt"

// SetupTokenPath is where that file lives.
//
// The DATA directory, not the install directory, for a reason that is not
// preference: on Linux the install directory is /usr/local/bin, which is
// root-owned and deliberately not writable by the unprivileged account the
// daemon runs as. A token file there could not be written at all. The data
// directory is the one place the daemon owns on every platform, and it is
// already where the configuration and its credentials live.
func SetupTokenPath(dataDir string) string {
	return filepath.Join(dataDir, SetupTokenFile)
}

// WriteSetupToken records the one-time setup token where an operator can find
// it.
//
// It exists because the token is printed to the daemon's stdout, and a service
// has no stdout: installed as a service -- which is what the product tells
// everybody to do -- the token is minted into a void. `set-password` is the
// better answer and leaves nothing at rest, but somebody part-way through a
// first-time setup with a blank settings page needs the token they were
// promised, and telling them to go and read the manual is not an answer.
//
// The file is written with a DACL that allows only administrators and the
// system account. If that cannot be applied, the file is DELETED and an error
// returned: a token readable by every local account is worse than no token
// file, because the token is the entire authority for claiming a fresh
// install, and the operator would have no idea it was readable.
//
// It is removed the moment a password exists, and it is useless afterwards in
// any case -- the token is spent on first use.
func WriteSetupToken(dataDir, token string) error {
	if token == "" {
		return RemoveSetupToken(dataDir)
	}
	path := SetupTokenPath(dataDir)

	body := "" +
		"NotifyMatrix one-time setup token\n" +
		"=================================\n\n" +
		token + "\n\n" +
		"Enter this in the interface to set the FIRST settings password.\n" +
		"It works once, and a new one is generated each time the daemon starts.\n" +
		"This file is deleted as soon as a password is set.\n\n" +
		"Anybody holding this can claim the settings page of this installation,\n" +
		"so it is readable only by administrators and by the account the daemon\n" +
		"runs as.\n\n" +
		"Being IN the Administrators group is not enough to open it. Windows\n" +
		"withholds those rights from a process until it elevates, so opening this\n" +
		"file directly reports \"access denied\" even for an administrator. Use an\n" +
		"elevated terminal, or let the program do it and prompt you:\n\n" +
		"    notifymatrix setup-token\n\n" +
		"If you would rather have no token on disk at all, delete this file and\n" +
		"run: notifymatrix set-password\n"

	// Created empty and locked down BEFORE the token is written into it, so
	// there is no window in which the value exists under inherited
	// permissions.
	f, err := os.OpenFile(path, os.O_CREATE|os.O_TRUNC|os.O_WRONLY, 0o600)
	if err != nil {
		return fmt.Errorf("config: creating %s: %w", path, err)
	}
	if err := f.Close(); err != nil {
		return fmt.Errorf("config: %w", err)
	}
	if err := restrictToAdmins(path); err != nil {
		os.Remove(path)
		return fmt.Errorf("config: %s could not be protected, so it was not "+
			"written -- use `notifymatrix set-password` instead: %w", path, err)
	}
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		os.Remove(path)
		return fmt.Errorf("config: writing %s: %w", path, err)
	}
	return nil
}

// RemoveSetupToken deletes the file, if it is there.
func RemoveSetupToken(dataDir string) error {
	err := os.Remove(SetupTokenPath(dataDir))
	if err != nil && !os.IsNotExist(err) {
		return fmt.Errorf("config: removing %s: %w", SetupTokenPath(dataDir), err)
	}
	return nil
}
