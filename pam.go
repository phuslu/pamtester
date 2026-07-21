// Package pamtester verifies and changes users' login passwords by calling
// the system's libpam directly via purego (no cgo required).
//
// The core type is Transaction, which corresponds to one PAM transaction
// (pam_start .. pam_end). Authenticate, AcctMgmt and ChangeAuthTok are its
// methods. The top-level functions CheckUserPassword and ChangeUserPassword
// are convenience wrappers around a single transaction.
//
// How it works:
//
//	Linux commands like login, su, sudo, and passwd all authenticate passwords
//	through PAM (Pluggable Authentication Modules). The flow is:
//	  1. pam_start()          Opens a PAM transaction and registers a
//	                           conversation callback function.
//	  2. pam_authenticate()   PAM internally uses modules like pam_unix.so,
//	                           which call back into the registered conversation
//	                           function to request the password. We supply the
//	                           password string to be verified in that callback.
//	  3. pam_acct_mgmt()      Checks account validity (expired, locked, ...).
//	  4. pam_end()            Closes the transaction.
//
//	The actual password comparison (reading /etc/shadow and hashing) is done by
//	pam_unix.so. Non-root processes can typically verify their own password:
//	when pam_unix lacks permission to read /etc/shadow directly, it delegates
//	to the setuid-root unix_chkpwd helper, so this library does not require
//	root privileges.
//
// Dependencies:
//
//	go get github.com/ebitengine/purego
package pamtester

import (
	"fmt"
)

// Options carries optional parameters for Start. The zero value is valid.
type Options struct {
	// Service selects the PAM service file under /etc/pam.d/.
	// Empty means the package-level default PamService.
	Service string

	// RHost, if non-empty, is set as PAM_RHOST — the remote host the request
	// originates from. Services performing authentication on behalf of remote
	// clients should set this so that modules like pam_faillock/pam_access
	// and audit logs record the real source.
	RHost string

	// TTY, if non-empty, is set as PAM_TTY.
	TTY string

	// RUser, if non-empty, is set as PAM_RUSER — the requesting user.
	RUser string
}

// Error is a PAM return code (from <security/_pam_types.h>) as a Go error.
// Errors returned by this package wrap an Error, so callers can classify
// failures with errors.Is:
//
//	if errors.Is(err, pamtester.ErrAuth) { ... wrong password ... }
type Error int32

// PAM return codes (Linux-PAM numbering).
const (
	ErrOpen                Error = 1  // PAM_OPEN_ERR
	ErrSymbol              Error = 2  // PAM_SYMBOL_ERR
	ErrService             Error = 3  // PAM_SERVICE_ERR
	ErrSystem              Error = 4  // PAM_SYSTEM_ERR
	ErrBuf                 Error = 5  // PAM_BUF_ERR
	ErrPermDenied          Error = 6  // PAM_PERM_DENIED
	ErrAuth                Error = 7  // PAM_AUTH_ERR — wrong password
	ErrCredInsufficient    Error = 8  // PAM_CRED_INSUFFICIENT
	ErrAuthinfoUnavail     Error = 9  // PAM_AUTHINFO_UNAVAIL
	ErrUserUnknown         Error = 10 // PAM_USER_UNKNOWN
	ErrMaxTries            Error = 11 // PAM_MAXTRIES
	ErrNewAuthTokReqd      Error = 12 // PAM_NEW_AUTHTOK_REQD — password correct but expired, must be changed
	ErrAcctExpired         Error = 13 // PAM_ACCT_EXPIRED
	ErrSession             Error = 14 // PAM_SESSION_ERR
	ErrCredUnavail         Error = 15 // PAM_CRED_UNAVAIL
	ErrCredExpired         Error = 16 // PAM_CRED_EXPIRED
	ErrCred                Error = 17 // PAM_CRED_ERR
	ErrNoModuleData        Error = 18 // PAM_NO_MODULE_DATA
	ErrConv                Error = 19 // PAM_CONV_ERR
	ErrAuthTok             Error = 20 // PAM_AUTHTOK_ERR
	ErrAuthTokRecovery     Error = 21 // PAM_AUTHTOK_RECOVERY_ERR — e.g. wrong old password in ChangeAuthTok
	ErrAuthTokLockBusy     Error = 22 // PAM_AUTHTOK_LOCK_BUSY
	ErrAuthTokDisableAging Error = 23 // PAM_AUTHTOK_DISABLE_AGING
	ErrTryAgain            Error = 24 // PAM_TRY_AGAIN
	ErrIgnore              Error = 25 // PAM_IGNORE
	ErrAbort               Error = 26 // PAM_ABORT
	ErrAuthTokExpired      Error = 27 // PAM_AUTHTOK_EXPIRED
	ErrModuleUnknown       Error = 28 // PAM_MODULE_UNKNOWN
	ErrBadItem             Error = 29 // PAM_BAD_ITEM
	ErrConvAgain           Error = 30 // PAM_CONV_AGAIN
	ErrIncomplete          Error = 31 // PAM_INCOMPLETE
)

func (e Error) Error() string {
	switch e {
	case ErrOpen:
		return "Failed to load module"
	case ErrSymbol:
		return "Symbol not found"
	case ErrService:
		return "Error in service module"
	case ErrSystem:
		return "System error"
	case ErrBuf:
		return "Memory buffer error"
	case ErrPermDenied:
		return "Permission denied"
	case ErrAuth:
		return "Authentication failure"
	case ErrCredInsufficient:
		return "Insufficient credentials to access authentication data"
	case ErrAuthinfoUnavail:
		return "Authentication service cannot retrieve authentication info"
	case ErrUserUnknown:
		return "User not known to the underlying authentication module"
	case ErrMaxTries:
		return "Have exhausted maximum number of retries for service"
	case ErrNewAuthTokReqd:
		return "Authentication token is no longer valid; new one required"
	case ErrAcctExpired:
		return "User account has expired"
	case ErrSession:
		return "Cannot make/remove an entry for the specified session"
	case ErrCredUnavail:
		return "Authentication service cannot retrieve user credentials"
	case ErrCredExpired:
		return "User credentials expired"
	case ErrCred:
		return "Failure setting user credentials"
	case ErrNoModuleData:
		return "No module specific data is present"
	case ErrConv:
		return "Conversation error"
	case ErrAuthTok:
		return "Authentication token manipulation error"
	case ErrAuthTokRecovery:
		return "Authentication information cannot be recovered"
	case ErrAuthTokLockBusy:
		return "Authentication token lock busy"
	case ErrAuthTokDisableAging:
		return "Authentication token aging disabled"
	case ErrTryAgain:
		return "Failed preliminary check by password service"
	case ErrIgnore:
		return "The return value should be ignored by PAM dispatch"
	case ErrAbort:
		return "Critical error - immediate abort"
	case ErrAuthTokExpired:
		return "Authentication token expired"
	case ErrModuleUnknown:
		return "Module is unknown"
	case ErrBadItem:
		return "Bad item passed to pam_*_item()"
	case ErrConvAgain:
		return "Conversation is waiting for event"
	}
	return fmt.Sprintf("PAM error %d", int32(e))
}
