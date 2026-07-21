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
	"runtime"
)

// PamService is the default PAM service configuration file under /etc/pam.d/,
// used when Options.Service is empty.
//
// On Linux it is "passwd", which exists on almost all distributions and
// carries the semantics of "verify/change the current user's password".
// Unlike "login", it does not impose extra restrictions such as securetty or
// allowed login time windows. If the target system lacks this file,
// alternatives like "login" or "su" can be used, or a minimal PAM service
// file can be created (typically just `auth required pam_unix.so`).
//
// On macOS it is "checkpw", the service Apple's own checkpw(3) API uses for
// password verification. macOS's /etc/pam.d/passwd must NOT be used to verify
// passwords: its auth stack is `auth required pam_permit.so`, which succeeds
// unconditionally for any password. Note that "checkpw" carries no password
// stack, so ChangeAuthTok on macOS requires Options{Service: "passwd"}.
var PamService = func() string {
	if runtime.GOOS == "darwin" {
		return "checkpw"
	}
	return "passwd"
}()

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

// errMessages mirrors Linux-PAM's pam_strerror() texts, so Error() is
// meaningful on any platform without calling into libpam.
var errMessages = map[Error]string{
	ErrOpen:                "Failed to load module",
	ErrSymbol:              "Symbol not found",
	ErrService:             "Error in service module",
	ErrSystem:              "System error",
	ErrBuf:                 "Memory buffer error",
	ErrPermDenied:          "Permission denied",
	ErrAuth:                "Authentication failure",
	ErrCredInsufficient:    "Insufficient credentials to access authentication data",
	ErrAuthinfoUnavail:     "Authentication service cannot retrieve authentication info",
	ErrUserUnknown:         "User not known to the underlying authentication module",
	ErrMaxTries:            "Have exhausted maximum number of retries for service",
	ErrNewAuthTokReqd:      "Authentication token is no longer valid; new one required",
	ErrAcctExpired:         "User account has expired",
	ErrSession:             "Cannot make/remove an entry for the specified session",
	ErrCredUnavail:         "Authentication service cannot retrieve user credentials",
	ErrCredExpired:         "User credentials expired",
	ErrCred:                "Failure setting user credentials",
	ErrNoModuleData:        "No module specific data is present",
	ErrConv:                "Conversation error",
	ErrAuthTok:             "Authentication token manipulation error",
	ErrAuthTokRecovery:     "Authentication information cannot be recovered",
	ErrAuthTokLockBusy:     "Authentication token lock busy",
	ErrAuthTokDisableAging: "Authentication token aging disabled",
	ErrTryAgain:            "Failed preliminary check by password service",
	ErrIgnore:              "The return value should be ignored by PAM dispatch",
	ErrAbort:               "Critical error - immediate abort",
	ErrAuthTokExpired:      "Authentication token expired",
	ErrModuleUnknown:       "Module is unknown",
	ErrBadItem:             "Bad item passed to pam_*_item()",
	ErrConvAgain:           "Conversation is waiting for event",
	ErrIncomplete:          "Application needs to call libpam again",
}

func (e Error) Error() string {
	if s, ok := errMessages[e]; ok {
		return s
	}
	return fmt.Sprintf("PAM error %d", int32(e))
}
