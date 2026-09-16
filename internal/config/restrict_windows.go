//go:build windows

package config

import (
	"fmt"

	"golang.org/x/sys/windows"
)

// restrictToAdmins replaces the file's permissions so that only
// administrators, the system account, and the account this process is running
// as can read it.
//
// PROTECTED is the load-bearing part. ProgramData and Program Files both grant
// read to Users by inheritance, so a token file written into either without
// dropping inherited entries is readable by every local account -- and nothing
// would say so. The token is the entire authority for claiming a fresh
// installation.
//
// The running account is included deliberately, and finding out why cost a
// test: with only Administrators and SYSTEM on the list, a daemon run in a
// console by a non-elevated administrator could not write its own token file.
// That is not a corner case, it is the exact thing an operator does when the
// service could not show them the token. The account holding the token in
// memory is not meaningfully protected from a file it just wrote.
func restrictToAdmins(path string) error {
	owner, err := currentUserSID()
	if err != nil {
		return fmt.Errorf("determining the current account: %w", err)
	}

	//	D:   discretionary ACL
	//	P    protected -- inherited entries are DROPPED, which is the point
	//	AI   auto-inherited, matching what Windows itself writes
	//	(A;;FA;;;BA)  allow, file all access, Builtin Administrators
	//	(A;;FA;;;SY)  allow, file all access, Local System
	//	(A;;FA;;;<sid>)  allow, file all access, the account running this
	sddl := "D:PAI(A;;FA;;;BA)(A;;FA;;;SY)(A;;FA;;;" + owner.String() + ")"

	sd, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
}

func currentUserSID() (*windows.SID, error) {
	tok := windows.GetCurrentProcessToken()
	u, err := tok.GetTokenUser()
	if err != nil {
		return nil, err
	}
	return u.User.Sid, nil
}
