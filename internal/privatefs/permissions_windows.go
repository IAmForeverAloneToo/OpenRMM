package privatefs

import (
	"errors"
	"os/exec"
	"path/filepath"
	"syscall"

	"golang.org/x/sys/windows"
)

func restrictDirectory(path string) error {
	token, err := syscall.OpenCurrentProcessToken()
	if err != nil {
		return errors.New("cannot read process identity for private directory permissions")
	}
	defer token.Close()
	identity, err := token.GetTokenUser()
	if err != nil {
		return errors.New("cannot read process account for private directory permissions")
	}
	sid, err := identity.User.Sid.String()
	if err != nil {
		return errors.New("cannot identify the account for private directory permissions")
	}
	// Resolve icacls from System32 rather than PATH, so a writable directory
	// earlier on PATH cannot substitute the program that sets these ACLs.
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return errors.New("cannot locate the Windows system directory")
	}
	// Only modify the newly created directory; files inherit the restricted ACL.
	command := exec.Command(filepath.Join(system, "icacls.exe"), path, "/inheritance:r", "/grant:r",
		"*"+sid+":(OI)(CI)F", "*S-1-5-18:(OI)(CI)F")
	if err := command.Run(); err != nil {
		return errors.New("cannot restrict private directory permissions")
	}
	return nil
}

// RestrictInstallation limits an existing installation folder to SYSTEM and
// Administrators. A folder created by Windows Installer under
// ProgramData inherits that folder's looser access; children inherit this.
func RestrictInstallation(path string) error {
	system, err := windows.GetSystemDirectory()
	if err != nil {
		return errors.New("cannot locate the Windows system directory")
	}
	command := exec.Command(filepath.Join(system, "icacls.exe"), path, "/inheritance:r", "/grant:r",
		"*S-1-5-18:(OI)(CI)F", "*S-1-5-32-544:(OI)(CI)F")
	if err := command.Run(); err != nil {
		return errors.New("cannot restrict installation permissions")
	}
	return nil
}
