//go:build windows

package pamtester

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"syscall"
	"unicode/utf16"

	"github.com/ebitengine/purego"
)

// ---------- Win32 constants ----------

const (
	logon32LogonNetwork    = 3 // LOGON32_LOGON_NETWORK — lightweight credential validation
	logon32ProviderDefault = 0 // LOGON32_PROVIDER_DEFAULT
)

// ---------- Win32 function bindings, initialized once per process ----------

var (
	initOnce sync.Once
	initErr  error

	logonUserW            func(username, domain, password *uint16, logonType, logonProvider uint32, token *uintptr) int32
	netUserChangePassword func(domainname, username, oldpassword, newpassword *uint16) uint32
	getUserNameW          func(buffer *uint16, size *uint32) int32
	closeHandle           func(handle uintptr) int32
	getLastError          func() uint32
)

func loadDLL(name string) (uintptr, error) {
	h, err := syscall.LoadLibrary(name)
	return uintptr(h), err
}

func mustLoadDLL(name string) uintptr {
	h, err := loadDLL(name)
	if err != nil {
		panic(fmt.Errorf("failed to load %s: %w", name, err))
	}
	return h
}

func initLibs() {
	defer func() {
		if r := recover(); r != nil {
			initErr = fmt.Errorf("PAM initialization failed: %v", r)
		}
	}()

	advapi32 := mustLoadDLL("advapi32.dll")
	netapi32 := mustLoadDLL("netapi32.dll")
	kernel32 := mustLoadDLL("kernel32.dll")

	purego.RegisterLibFunc(&logonUserW, advapi32, "LogonUserW")
	purego.RegisterLibFunc(&getUserNameW, advapi32, "GetUserNameW")
	purego.RegisterLibFunc(&netUserChangePassword, netapi32, "NetUserChangePassword")
	purego.RegisterLibFunc(&closeHandle, kernel32, "CloseHandle")
	purego.RegisterLibFunc(&getLastError, kernel32, "GetLastError")
}

// ---------- UTF-16 helpers ----------

func utf16FromString(s string) []uint16 {
	return utf16.Encode(append([]rune(s), 0))
}

func utf16ToGoString(s []uint16) string {
	for i, v := range s {
		if v == 0 {
			s = s[:i]
			break
		}
	}
	return string(utf16.Decode(s))
}

// ---------- Error mapping ----------

// mapWinError maps common Win32 error codes to PAM error codes so that
// callers can classify failures with errors.Is just like on Linux/macOS.
func mapWinError(code uint32) Error {
	switch code {
	case 1326: // ERROR_LOGON_FAILURE
		return ErrAuth
	case 1330: // ERROR_PASSWORD_EXPIRED
		return ErrNewAuthTokReqd
	case 1331: // ERROR_ACCOUNT_DISABLED
		return ErrAcctExpired
	case 1793: // ERROR_ACCOUNT_EXPIRED
		return ErrAcctExpired
	case 1909: // ERROR_ACCOUNT_LOCKED_OUT
		return ErrMaxTries
	case 5: // ERROR_ACCESS_DENIED
		return ErrPermDenied
	case 86: // ERROR_INVALID_PASSWORD
		return ErrAuthTokRecovery
	case 2221: // NERR_UserNotFound
		return ErrUserUnknown
	case 2226: // NERR_PasswordTooShort
		return ErrAuthTok
	case 2245: // NERR_PasswordTooShort (duplicate/close)
		return ErrAuthTok
	default:
		return ErrSystem
	}
}

// ---------- Transaction ----------

// Transaction represents one "PAM-like" transaction backed by Win32.
// Obtain one with Start, and always Close it.
type Transaction struct {
	mu     sync.Mutex
	user   string  // account name (without domain prefix)
	domain string  // parsed from user (domain\user format); empty = local
	token  uintptr // token from LogonUserW, valid after successful Authenticate
	closed bool
}

// Start opens a new transaction for user. If user is empty the current
// process user is used (via GetUserNameW). On Windows opts.RHost, opts.TTY
// and opts.RUser are ignored — there are no PAM items to set.
func Start(user string, opts *Options) (*Transaction, error) {
	initOnce.Do(initLibs)
	if initErr != nil {
		return nil, initErr
	}

	if user == "" {
		var size uint32 = 256
		buf := make([]uint16, size)
		for {
			ret := getUserNameW(&buf[0], &size)
			if ret != 0 {
				user = utf16ToGoString(buf)
				break
			}
			// Buffer too small; size now holds the required length.
			if size > 1024 {
				return nil, errors.New("GetUserNameW: buffer too large")
			}
			buf = make([]uint16, size)
		}
	}

	// Split domain\user if present (typical Windows account format).
	domain := ""
	if idx := strings.IndexByte(user, '\\'); idx >= 0 {
		domain = user[:idx]
		user = user[idx+1:]
	}

	return &Transaction{user: user, domain: domain}, nil
}

// Authenticate verifies password by calling LogonUserW with
// LOGON32_LOGON_NETWORK — a lightweight logon that validates credentials
// without creating a full interactive session. Returns nil if the password
// is correct; a wrong password yields an error matching ErrAuth (use
// errors.Is). Account-disabled and password-expired states are mapped to
// ErrAcctExpired and ErrNewAuthTokReqd respectively.
//
// On Windows, LogonUserW already performs the checks that pam_acct_mgmt
// would do on Linux; AcctMgmt is a no-op that returns nil.
func (t *Transaction) Authenticate(password string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("pamtester: transaction already closed")
	}

	// Close any token from a previous Authenticate call.
	if t.token != 0 {
		closeHandle(t.token)
		t.token = 0
	}

	userW := utf16FromString(t.user)
	passwordW := utf16FromString(password)
	var domainW *uint16
	if t.domain != "" {
		d := utf16FromString(t.domain)
		domainW = &d[0]
	}

	var token uintptr
	ret := logonUserW(
		&userW[0],
		domainW,
		&passwordW[0],
		logon32LogonNetwork,
		logon32ProviderDefault,
		&token,
	)
	if ret == 0 {
		code := getLastError()
		return fmt.Errorf("pam_authenticate: %w", mapWinError(code))
	}
	t.token = token
	return nil
}

// AcctMgmt is a no-op on Windows: LogonUserW already validates account
// status (enabled, not expired, not locked) during Authenticate, so there
// is no separate account-management step.
func (t *Transaction) AcctMgmt() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("pamtester: transaction already closed")
	}
	return nil
}

// ChangeAuthTok changes the user's password via NetUserChangePassword. When
// run by a non-administrator, the old password is required and a wrong value
// yields an error matching ErrAuthTokRecovery. Administrators may pass an
// empty oldPassword to force a reset (domain policy permitting).
//
// The new password must meet the system's password complexity requirements;
// failures (too short, too simple, matches history) yield an error matching
// ErrAuthTok.
func (t *Transaction) ChangeAuthTok(oldPassword, newPassword string) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("pamtester: transaction already closed")
	}

	userW := utf16FromString(t.user)
	oldW := utf16FromString(oldPassword)
	newW := utf16FromString(newPassword)
	var domainW *uint16
	if t.domain != "" {
		d := utf16FromString(t.domain)
		domainW = &d[0]
	}

	ret := netUserChangePassword(domainW, &userW[0], &oldW[0], &newW[0])
	if ret != 0 {
		return fmt.Errorf("pam_chauthtok: %w", mapWinError(ret))
	}
	return nil
}

// Close releases resources (the token handle from LogonUserW if any).
// Calling Close more than once is harmless.
func (t *Transaction) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true

	if t.token != 0 {
		closeHandle(t.token)
		t.token = 0
	}
	return nil
}
