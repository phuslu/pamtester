//go:build windows && !nopamtester

package pamtester

import (
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
	"syscall"
	"unicode/utf16"
	"unsafe"
)

// PamService is the default PAM service configuration file under /etc/pam.d/,
// used when Options.Service is empty.
var PamService = "passwd"

// ---------- Win32 constants ----------

const (
	logon32LogonNetwork    = 3 // LOGON32_LOGON_NETWORK — lightweight credential validation
	logon32ProviderDefault = 0 // LOGON32_PROVIDER_DEFAULT
)

// ---------- Win32 function bindings, initialized once per process ----------

var (
	initOnce sync.Once
	initErr  error

	advapi32 = syscall.NewLazyDLL("advapi32.dll")
	netapi32 = syscall.NewLazyDLL("netapi32.dll")
	kernel32 = syscall.NewLazyDLL("kernel32.dll")

	logonUserW            = advapi32.NewProc("LogonUserW")
	netUserChangePassword = netapi32.NewProc("NetUserChangePassword")
	closeHandle           = kernel32.NewProc("CloseHandle")
)

func initLibs() {
	for _, proc := range []*syscall.LazyProc{
		logonUserW,
		netUserChangePassword,
		closeHandle,
	} {
		if err := proc.Find(); err != nil {
			initErr = fmt.Errorf("failed to initialize %s: %w", proc.Name, err)
			return
		}
	}
}

// lastErrCode extracts the last-error value returned by syscall.Proc.Call.
// Its error is always a syscall.Errno, even when the Win32 call succeeds.
func lastErrCode(err error) uint32 {
	if errno, ok := err.(syscall.Errno); ok {
		return uint32(errno)
	}
	return 0
}

// ---------- UTF-16 helpers ----------

func utf16FromString(s string) []uint16 {
	return utf16.Encode(append([]rune(s), 0))
}

// ---------- Error mapping ----------

// mapWinError maps common Win32 / LAN Manager error codes to PAM error codes
// so that callers can classify failures with errors.Is just like on
// Linux/macOS. Codes without a closer equivalent map to ErrSystem.
func mapWinError(code uint32) Error {
	switch code {
	case 5: // ERROR_ACCESS_DENIED
		return ErrPermDenied
	case 86: // ERROR_INVALID_PASSWORD
		return ErrAuthTokRecovery
	case 1311: // ERROR_NO_LOGON_SERVERS
		return ErrAuthinfoUnavail
	case 1317: // ERROR_NO_SUCH_USER
		return ErrUserUnknown
	case 1326: // ERROR_LOGON_FAILURE
		return ErrAuth
	case 1327: // ERROR_ACCOUNT_RESTRICTION
		return ErrPermDenied
	case 1328: // ERROR_INVALID_LOGON_HOURS
		return ErrPermDenied
	case 1329: // ERROR_INVALID_WORKSTATION
		return ErrPermDenied
	case 1330: // ERROR_PASSWORD_EXPIRED
		return ErrNewAuthTokReqd
	case 1331: // ERROR_ACCOUNT_DISABLED
		return ErrAcctExpired
	case 1355: // ERROR_NO_SUCH_DOMAIN
		return ErrAuthinfoUnavail
	case 1385: // ERROR_LOGON_TYPE_NOT_GRANTED
		return ErrPermDenied
	case 1793: // ERROR_ACCOUNT_EXPIRED
		return ErrAcctExpired
	case 1907: // ERROR_PASSWORD_MUST_CHANGE
		return ErrNewAuthTokReqd
	case 1909: // ERROR_ACCOUNT_LOCKED_OUT
		return ErrMaxTries
	case 2221: // NERR_UserNotFound
		return ErrUserUnknown
	case 2243: // NERR_PasswordCantChange
		return ErrAuthTok
	case 2244: // NERR_PasswordHistConflict
		return ErrAuthTok
	case 2245: // NERR_PasswordTooShort
		return ErrAuthTok
	case 2246: // NERR_PasswordTooRecent
		return ErrAuthTok
	default:
		return ErrSystem
	}
}

// winError wraps both the mapped PAM Error and the original Win32 code, so
// errors.Is works with the portable constants while the native code (and
// its system message) is not lost.
func winError(code uint32) error {
	return fmt.Errorf("%w (%w)", mapWinError(code), syscall.Errno(code))
}

// ---------- Transaction ----------

// Transaction represents one "PAM-like" transaction backed by Win32.
// Obtain one with Start, and always Close it.
type Transaction struct {
	mu        sync.Mutex
	user      string // account name (without domain prefix)
	domain    string // parsed from user (domain\user format); empty = unqualified
	allowNull bool   // Options.AllowNullAuthTok
	closed    bool
}

// Start opens a new transaction for user, given as "user", "DOMAIN\user",
// ".\user" (local account) or "user@domain.tld". If user is empty the
// current process user is used, in its fully qualified DOMAIN\user form. On
// Windows opts.RHost, opts.TTY and opts.RUser are ignored — there are no PAM
// items to set.
//
// An unqualified name is resolved by Windows: LogonUserW searches the local
// account database and then trusted domains, while NetUserChangePassword
// targets the caller's logon domain. On a domain-joined machine, qualify
// local accounts as ".\user" so ChangeAuthTok changes the local account.
func Start(user string, opts *Options) (*Transaction, error) {
	initOnce.Do(initLibs)
	if initErr != nil {
		return nil, initErr
	}

	if user == "" {
		u, err := currentUser()
		if err != nil {
			return nil, err
		}
		user = u
	}

	if err := checkNUL(user); err != nil {
		return nil, err
	}

	// Split domain\user if present (typical Windows account format).
	domain := ""
	if idx := strings.IndexByte(user, '\\'); idx >= 0 {
		domain = user[:idx]
		user = user[idx+1:]
	}

	t := &Transaction{user: user, domain: domain}
	if opts != nil {
		t.allowNull = opts.AllowNullAuthTok
	}
	return t, nil
}

// Authenticate verifies password by calling LogonUserW with
// LOGON32_LOGON_NETWORK — a lightweight logon that validates credentials
// without creating a full interactive session. Returns nil if the password
// is correct; a wrong password yields an error matching ErrAuth (use
// errors.Is). Account-disabled and password-expired states are mapped to
// ErrAcctExpired and ErrNewAuthTokReqd respectively. An empty password is
// rejected with ErrAuth unless Options.AllowNullAuthTok is set.
//
// On Windows, LogonUserW already performs the checks that pam_acct_mgmt
// would do on Linux; AcctMgmt is a no-op that returns nil.
func (t *Transaction) Authenticate(password string) error {
	if err := checkNUL(password); err != nil {
		return err
	}
	if password == "" && !t.allowNull {
		return errNullAuthTok
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("pamtester: transaction already closed")
	}

	userW := utf16FromString(t.user)
	passwordW := utf16FromString(password)
	var domainW *uint16
	if t.domain != "" {
		d := utf16FromString(t.domain)
		domainW = &d[0]
	}

	var token uintptr
	ret, _, callErr := logonUserW.Call(
		uintptr(unsafe.Pointer(&userW[0])),
		uintptr(unsafe.Pointer(domainW)),
		uintptr(unsafe.Pointer(&passwordW[0])),
		uintptr(logon32LogonNetwork),
		uintptr(logon32ProviderDefault),
		uintptr(unsafe.Pointer(&token)),
	)
	if ret == 0 {
		return fmt.Errorf("pam_authenticate: %w", winError(lastErrCode(callErr)))
	}
	// Only the credential check matters; the logon token itself is unused.
	closeHandle.Call(token)
	return nil
}

// AuthenticateConv asks conv for the password with a single PromptEchoOff
// "Password: " prompt — Windows has no PAM conversation — and then behaves
// like Authenticate. An error from conv is returned wrapped together with
// ErrConv.
func (t *Transaction) AuthenticateConv(conv ConvFunc) error {
	if conv == nil {
		return errors.New("pamtester: nil ConvFunc")
	}
	password, err := conv(PromptEchoOff, "Password: ")
	if err != nil {
		return fmt.Errorf("pam_authenticate: %w: %w", ErrConv, err)
	}
	return t.Authenticate(password)
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
	if err := checkNUL(oldPassword, newPassword); err != nil {
		return err
	}
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("pamtester: transaction already closed")
	}

	userW := utf16FromString(t.user)
	oldW := utf16FromString(oldPassword)
	newW := utf16FromString(newPassword)
	var domainW *uint16
	if domain := t.domain; domain != "" {
		// "." means the local machine for LogonUserW, but
		// NetUserChangePassword needs an actual server name.
		if domain == "." {
			h, err := os.Hostname()
			if err != nil {
				return fmt.Errorf("pam_chauthtok: %w", err)
			}
			domain = h
		}
		d := utf16FromString(domain)
		domainW = &d[0]
	}

	ret, _, _ := netUserChangePassword.Call(
		uintptr(unsafe.Pointer(domainW)),
		uintptr(unsafe.Pointer(&userW[0])),
		uintptr(unsafe.Pointer(&oldW[0])),
		uintptr(unsafe.Pointer(&newW[0])),
	)
	if ret != 0 {
		return fmt.Errorf("pam_chauthtok: %w", winError(uint32(ret)))
	}
	return nil
}

// ChangeAuthTokConv asks conv for the current password, the new password
// and its confirmation (three PromptEchoOff prompts, as passwd(1) would) and
// then behaves like ChangeAuthTok. A mismatched confirmation yields an error
// matching ErrAuthTok; an error from conv is returned wrapped together with
// ErrConv.
func (t *Transaction) ChangeAuthTokConv(conv ConvFunc) error {
	if conv == nil {
		return errors.New("pamtester: nil ConvFunc")
	}
	var answers [3]string
	for i, prompt := range []string{"Current password: ", "New password: ", "Retype new password: "} {
		reply, err := conv(PromptEchoOff, prompt)
		if err != nil {
			return fmt.Errorf("pam_chauthtok: %w: %w", ErrConv, err)
		}
		answers[i] = reply
	}
	if answers[1] != answers[2] {
		return fmt.Errorf("pam_chauthtok: %w (passwords do not match)", ErrAuthTok)
	}
	return t.ChangeAuthTok(answers[0], answers[1])
}

// Messages always returns nil on Windows: the Win32 APIs used here do not
// emit PAM-style informational messages.
func (t *Transaction) Messages() []string {
	return nil
}

// Close ends the transaction. Calling Close more than once is harmless.
func (t *Transaction) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true
	return nil
}
