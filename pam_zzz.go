//go:build nopamtester || !(linux || darwin || windows || (freebsd && cgo))

package pamtester

import (
	"errors"
)

// PamService is the default PAM service configuration file under /etc/pam.d/,
// used when Options.Service is empty.
var PamService = "passwd"

// Transaction represents one PAM transaction (pam_start .. pam_end). Real
// backends exist for Linux, macOS, Windows and FreeBSD (with cgo); on other platforms, or when
// built with the nopamtester tag, every operation falls back to this stub and
// Start always fails with errors.ErrUnsupported.
type Transaction struct{}

// Start opens a PAM transaction for user. Unsupported: with the nopamtester
// tag set, or on this platform, no real PAM backend is compiled in.
func Start(user string, opts *Options) (*Transaction, error) {
	return nil, errors.ErrUnsupported
}

// Authenticate verifies password via pam_authenticate. Unsupported with the
// nopamtester tag or on this platform.
func (t *Transaction) Authenticate(password string) error {
	return errors.ErrUnsupported
}

// AuthenticateConv runs pam_authenticate with a custom conversation.
// Unsupported with the nopamtester tag or on this platform.
func (t *Transaction) AuthenticateConv(conv ConvFunc) error {
	return errors.ErrUnsupported
}

// AcctMgmt checks account validity via pam_acct_mgmt. Unsupported with the
// nopamtester tag or on this platform.
func (t *Transaction) AcctMgmt() error {
	return errors.ErrUnsupported
}

// ChangeAuthTok changes the user's password via pam_chauthtok. Unsupported
// with the nopamtester tag or on this platform.
func (t *Transaction) ChangeAuthTok(oldPassword, newPassword string) error {
	return errors.ErrUnsupported
}

// ChangeAuthTokConv runs pam_chauthtok with a custom conversation.
// Unsupported with the nopamtester tag or on this platform.
func (t *Transaction) ChangeAuthTokConv(conv ConvFunc) error {
	return errors.ErrUnsupported
}

// User returns the PAM_USER item. Unsupported with the nopamtester tag or
// on this platform.
func (t *Transaction) User() (string, error) {
	return "", errors.ErrUnsupported
}

// Messages always returns nil in the fallback implementation.
func (t *Transaction) Messages() []string {
	return nil
}

// Close ends the transaction. Nothing to do in the fallback implementation.
func (t *Transaction) Close() error {
	return nil
}
