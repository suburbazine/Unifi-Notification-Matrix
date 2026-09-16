//go:build windows

package fileperm

import (
	"fmt"
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// Restrict replaces a file's permissions so that only administrators, the
// system account, and the accounts that own this installation can read it.
//
// PROTECTED is the load-bearing part. ProgramData and Program Files both grant
// read to Users by inheritance -- and full control to Everyone on the
// directories created under them -- so a file written into either without
// dropping inherited entries is readable by every local account, and nothing
// would say so.
func Restrict(path string) error {
	dacl, err := ownersDACL(path, false)
	if err != nil {
		return err
	}
	return apply(path, dacl)
}

// RestrictDir does the same for a directory, and makes everything created
// inside it inherit the restriction.
//
// Necessary alongside Restrict, and found by looking at a real installation
// rather than at the code. C:\ProgramData grants Everyone FULL CONTROL to the
// directories created under it. Full control of a DIRECTORY carries the right
// to delete and create files in it, so locking down config.yaml on its own
// still left any local account able to delete it and drop in their own --
// which a service running as LocalSystem would then read and act on. The file
// permissions were the visible half of the problem; this was the half that
// mattered more.
func RestrictDir(path string) error {
	dacl, err := ownersDACL(path, true)
	if err != nil {
		return err
	}
	return apply(path, dacl)
}

// ownersDACL builds the access list.
//
// The membership is deliberately wider than "administrators and SYSTEM", and
// the reason is UAC rather than generosity. An administrator's token is
// DENY-ONLY for BUILTIN\Administrators until the process elevates, so a DACL
// naming only that group locks the operator out of their own data directory
// from any ordinary terminal -- and `notifymatrix incidents`, `setup` and
// `set-password` are all things this product insists must work from one. That
// is the same trap the setup token fell into, discovered there by an operator
// who had done everything right and got "access denied" from Notepad.
//
// So the accounts that already own this installation keep their access: the
// account running this process, the owner of the object itself, and the owner
// of the data directory it sits in. What goes away is BUILTIN\Users and
// Everyone, which is the entire point.
func ownersDACL(path string, container bool) (*windows.ACL, error) {
	sids := []string{"BA", "SY"} // administrators, local system

	add := func(s *windows.SID) {
		if s == nil {
			return
		}
		str := s.String()
		for _, have := range sids {
			if strings.EqualFold(have, str) {
				return
			}
		}
		sids = append(sids, str)
	}

	self, err := currentUserSID()
	if err != nil {
		return nil, fmt.Errorf("determining the current account: %w", err)
	}
	add(self)
	if o, err := ownerOf(path); err == nil {
		add(o)
	}
	// The directory's owner, so a file owned by Administrators inside a data
	// directory owned by a person does not quietly become elevation-only.
	if parent := filepath.Dir(path); parent != path {
		if o, err := ownerOf(parent); err == nil {
			add(o)
		}
	}

	//	D:   discretionary ACL
	//	P    protected -- inherited entries are DROPPED, which is the point
	//	AI   auto-inherited, matching what Windows itself writes
	//	OICI on a directory, so everything created inside inherits this
	//	FA   file all access
	flags := ""
	if container {
		flags = "OICI"
	}
	var b strings.Builder
	b.WriteString("D:PAI")
	for _, s := range sids {
		fmt.Fprintf(&b, "(A;%s;FA;;;%s)", flags, s)
	}

	sd, err := windows.SecurityDescriptorFromString(b.String())
	if err != nil {
		return nil, err
	}
	dacl, _, err := sd.DACL()
	return dacl, err
}

func apply(path string, dacl *windows.ACL) error {
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
}

func ownerOf(path string) (*windows.SID, error) {
	sd, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil, err
	}
	owner, _, err := sd.Owner()
	return owner, err
}

func currentUserSID() (*windows.SID, error) {
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid, nil
}
