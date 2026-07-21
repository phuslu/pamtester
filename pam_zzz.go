//go:build !linux

package pamtester

import (
	"errors"
)

// Transaction represents one PAM transaction (pam_start .. pam_end).
// PAM is only available on Linux; on other platforms Start always fails.
type Transaction struct{}

// Start opens a PAM transaction for user. Unsupported on this platform.
func Start(user string, opts *Options) (*Transaction, error) {
	return nil, errors.ErrUnsupported
}

// Authenticate verifies password via pam_authenticate. Unsupported on this platform.
func (t *Transaction) Authenticate(password string) error {
	return errors.ErrUnsupported
}

// AcctMgmt checks account validity via pam_acct_mgmt. Unsupported on this platform.
func (t *Transaction) AcctMgmt() error {
	return errors.ErrUnsupported
}

// ChangeAuthTok changes the user's password via pam_chauthtok. Unsupported on this platform.
func (t *Transaction) ChangeAuthTok(oldPassword, newPassword string) error {
	return errors.ErrUnsupported
}

// Close ends the transaction. Unsupported on this platform.
func (t *Transaction) Close() error {
	return nil
}
