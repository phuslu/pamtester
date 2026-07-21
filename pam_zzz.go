//go:build !linux

package pamtester

import (
	"errors"
)

// PamService specifies the PAM service configuration file under /etc/pam.d/.
// "passwd" exists on almost all distributions and carries the semantics of
// "verify/change the current user's password". Unlike "login", it does not
// impose extra restrictions such as securetty or allowed login time windows.
// If the target system lacks this file, alternatives like "login" or "su" can
// be used, or a minimal PAM service file can be created (typically just
// `auth required pam_unix.so`).
var PamService = "passwd"

// CheckUserPassword verifies whether password is the login password for the
// given user. Returns nil if the password is correct; returns a non-nil error
// if the password is wrong, the user does not exist, or the PAM environment is
// misconfigured.
func CheckUserPassword(user, password string) error {
	return errors.ErrUnsupported
}
