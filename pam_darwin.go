//go:build darwin

package pamtester

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// ---------- PAM constants (from <security/pam_constants.h>) ----------
//
// macOS ships OpenPAM, whose return codes are numbered differently from
// Linux-PAM (e.g. PAM_AUTH_ERR is 9 here but 7 on Linux). Native codes are
// therefore translated to the portable Error constants via openpamError
// before being surfaced, and the conversation callback returns native codes.

const (
	pamSuccess = 0 // PAM_SUCCESS

	// conversation message styles
	pamPromptEchoOff = 1 // prompt for input without echo — typical "Password:" prompt
	pamPromptEchoOn  = 2 // prompt for input with echo
	pamErrorMsg      = 3 // error message, no response expected
	pamTextInfo      = 4 // informational message, no response expected

	// pam_set_item item types
	pamItemTTY     = 3 // PAM_TTY
	pamItemRHost   = 4 // PAM_RHOST
	pamItemAuthTok = 6 // PAM_AUTHTOK
	pamItemRUser   = 8 // PAM_RUSER

	// native OpenPAM return codes needed by the conversation callback
	openpamBufErr  = 5 // PAM_BUF_ERR
	openpamConvErr = 6 // PAM_CONV_ERR
)

// openpamErrors maps native OpenPAM return codes to the portable,
// Linux-PAM-numbered Error constants exposed by this package, so that
// errors.Is(err, ErrAuth) etc. classify correctly on macOS too.
var openpamErrors = [...]Error{
	1:  ErrOpen,                // PAM_OPEN_ERR
	2:  ErrSymbol,              // PAM_SYMBOL_ERR
	3:  ErrService,             // PAM_SERVICE_ERR
	4:  ErrSystem,              // PAM_SYSTEM_ERR
	5:  ErrBuf,                 // PAM_BUF_ERR
	6:  ErrConv,                // PAM_CONV_ERR
	7:  ErrPermDenied,          // PAM_PERM_DENIED
	8:  ErrMaxTries,            // PAM_MAXTRIES
	9:  ErrAuth,                // PAM_AUTH_ERR
	10: ErrNewAuthTokReqd,      // PAM_NEW_AUTHTOK_REQD
	11: ErrCredInsufficient,    // PAM_CRED_INSUFFICIENT
	12: ErrAuthinfoUnavail,     // PAM_AUTHINFO_UNAVAIL
	13: ErrUserUnknown,         // PAM_USER_UNKNOWN
	14: ErrCredUnavail,         // PAM_CRED_UNAVAIL
	15: ErrCredExpired,         // PAM_CRED_EXPIRED
	16: ErrCred,                // PAM_CRED_ERR
	17: ErrAcctExpired,         // PAM_ACCT_EXPIRED
	18: ErrAuthTokExpired,      // PAM_AUTHTOK_EXPIRED
	19: ErrSession,             // PAM_SESSION_ERR
	20: ErrAuthTok,             // PAM_AUTHTOK_ERR
	21: ErrAuthTokRecovery,     // PAM_AUTHTOK_RECOVERY_ERR
	22: ErrAuthTokLockBusy,     // PAM_AUTHTOK_LOCK_BUSY
	23: ErrAuthTokDisableAging, // PAM_AUTHTOK_DISABLE_AGING
	24: ErrNoModuleData,        // PAM_NO_MODULE_DATA
	25: ErrIgnore,              // PAM_IGNORE
	26: ErrAbort,               // PAM_ABORT
	27: ErrTryAgain,            // PAM_TRY_AGAIN
	28: ErrModuleUnknown,       // PAM_MODULE_UNKNOWN
}

func openpamError(ret int32) Error {
	if int(ret) < len(openpamErrors) && openpamErrors[ret] != 0 {
		return openpamErrors[ret]
	}
	// PAM_DOMAIN_UNKNOWN and anything newer have no portable equivalent
	return ErrSystem
}

// ---------- C struct memory layouts (amd64 / arm64) ----------

// struct pam_message { int msg_style; const char *msg; };
type pamMessage struct {
	msgStyle int32
	_        [4]byte // padding to 8-byte alignment, matching C compiler inserted padding
	msg      uintptr
}

// struct pam_response { char *resp; int resp_retcode; };
type pamResponse struct {
	resp        uintptr
	respRetcode int32
	_           [4]byte
}

// struct pam_conv { int (*conv)(...); void *appdata_ptr; };
type pamConv struct {
	conv    uintptr
	appData uintptr
}

// ---------- libpam / libc function bindings, initialized once per process ----------

var (
	initOnce sync.Once
	initErr  error

	pamStart        func(service, user string, conv *pamConv, pamh *uintptr) int32
	pamAuthenticate func(pamh uintptr, flags int32) int32
	pamAcctMgmt     func(pamh uintptr, flags int32) int32
	pamChauthtok    func(pamh uintptr, flags int32) int32
	pamSetItem      func(pamh uintptr, itemType int32, item string) int32
	pamEnd          func(pamh uintptr, status int32) int32

	cMalloc func(size uintptr) uintptr
	cFree   func(ptr uintptr)
	cStrdup func(s string) uintptr
	cStrlen func(p uintptr) uintptr

	// convCallback is the single C-callable conversation trampoline shared by
	// all transactions. purego.NewCallback slots are limited and never freed,
	// so it must be created exactly once, not per call; the transaction is
	// looked up from appdata_ptr in the registry below.
	convCallback uintptr
)

// registry mapping the appdata_ptr passed to PAM back to a live *Transaction.
var (
	convMu     sync.Mutex
	convNextID uintptr = 1
	convTxns           = map[uintptr]*Transaction{}
)

func dlopenAny(names ...string) (uintptr, error) {
	var lastErr error
	for _, n := range names {
		h, err := purego.Dlopen(n, purego.RTLD_NOW|purego.RTLD_GLOBAL)
		if err == nil {
			return h, nil
		}
		lastErr = err
	}
	return 0, fmt.Errorf("failed to load any of %v: %w", names, lastErr)
}

func initLibs() {
	// RegisterLibFunc panics when a symbol is missing. Recover and convert
	// to an error to avoid crashing the calling program on unusual systems.
	defer func() {
		if r := recover(); r != nil {
			initErr = fmt.Errorf("PAM initialization failed: %v", r)
		}
	}()

	libpam, err := dlopenAny("libpam.2.dylib", "libpam.dylib")
	if err != nil {
		initErr = fmt.Errorf("failed to load libpam (PAM may not be installed): %w", err)
		return
	}
	libc, err := dlopenAny("libSystem.B.dylib", "libc.dylib")
	if err != nil {
		initErr = fmt.Errorf("failed to load libc: %w", err)
		return
	}

	purego.RegisterLibFunc(&pamStart, libpam, "pam_start")
	purego.RegisterLibFunc(&pamAuthenticate, libpam, "pam_authenticate")
	purego.RegisterLibFunc(&pamAcctMgmt, libpam, "pam_acct_mgmt")
	purego.RegisterLibFunc(&pamChauthtok, libpam, "pam_chauthtok")
	purego.RegisterLibFunc(&pamSetItem, libpam, "pam_set_item")
	purego.RegisterLibFunc(&pamEnd, libpam, "pam_end")

	purego.RegisterLibFunc(&cMalloc, libc, "malloc")
	purego.RegisterLibFunc(&cFree, libc, "free")
	purego.RegisterLibFunc(&cStrdup, libc, "strdup")
	purego.RegisterLibFunc(&cStrlen, libc, "strlen")

	convCallback = purego.NewCallback(convHandler)
}

// cptr converts a C pointer held in a uintptr to unsafe.Pointer. These values
// come from malloc/PAM — they are never Go pointers, so the conversion is
// safe; the indirection keeps go vet's unsafeptr check from flagging it.
func cptr(p uintptr) unsafe.Pointer {
	return *(*unsafe.Pointer)(unsafe.Pointer(&p))
}

// goString copies a NUL-terminated C string into a Go string.
func goString(p uintptr) string {
	if p == 0 {
		return ""
	}
	n := cStrlen(p)
	if n == 0 {
		return ""
	}
	return string(unsafe.Slice((*byte)(cptr(p)), n))
}

// respondFunc answers a single PAM prompt (style is pamPromptEchoOff/On).
// Returning ok=false aborts the conversation with PAM_CONV_ERR.
type respondFunc func(style int32, prompt string) (reply string, ok bool)

// convHandler is the PAM conversation function shared by all transactions;
// appdata is the registry id of the owning Transaction.
//
// The returned respArray and each resp string must be allocated with C's
// malloc/strdup — PAM will free them itself when done. Using Go-allocated
// memory here would cause PAM to attempt freeing an address not managed by
// libc, resulting in a crash. On failure we must free them ourselves, since
// PAM only takes ownership when we return PAM_SUCCESS.
func convHandler(numMsg int32, msgs uintptr, respOut uintptr, appdata uintptr) int32 {
	convMu.Lock()
	t := convTxns[appdata]
	convMu.Unlock()
	if t == nil {
		return openpamConvErr
	}
	if numMsg <= 0 {
		return pamSuccess
	}
	n := int(numMsg)

	// msgs is `const struct pam_message **`, i.e. an array of n pointers
	msgPtrs := unsafe.Slice((*uintptr)(cptr(msgs)), n)

	respArray := cMalloc(uintptr(n) * unsafe.Sizeof(pamResponse{}))
	if respArray == 0 {
		return openpamBufErr
	}
	responses := unsafe.Slice((*pamResponse)(cptr(respArray)), n)
	for i := range responses {
		responses[i] = pamResponse{}
	}

	fail := func(code int32) int32 {
		for i := range responses {
			if responses[i].resp != 0 {
				cFree(responses[i].resp)
			}
		}
		cFree(respArray)
		return code
	}

	for i := 0; i < n; i++ {
		m := (*pamMessage)(cptr(msgPtrs[i]))
		switch m.msgStyle {
		case pamPromptEchoOff, pamPromptEchoOn:
			// t.respond is only read here, on the same thread that holds
			// t.mu inside the pam_* call — no extra locking needed.
			if t.respond == nil {
				return fail(openpamConvErr)
			}
			reply, ok := t.respond(m.msgStyle, goString(m.msg))
			if !ok {
				return fail(openpamConvErr)
			}
			if responses[i].resp = cStrdup(reply); responses[i].resp == 0 {
				return fail(openpamBufErr)
			}
		default:
			// PAM_ERROR_MSG / PAM_TEXT_INFO messages need no response; resp stays NULL
		}
	}

	*(*uintptr)(cptr(respOut)) = respArray
	return pamSuccess
}

// ---------- Transaction ----------

// Transaction represents one PAM transaction, i.e. a pam_start .. pam_end
// lifetime. Obtain one with Start, and always Close it. A Transaction is safe
// for sequential use; its methods serialize via an internal mutex.
type Transaction struct {
	mu         sync.Mutex
	pamh       uintptr
	convMem    uintptr // C-heap allocated struct pam_conv
	id         uintptr // key in convTxns
	respond    respondFunc
	lastStatus int32
	closed     bool
}

// Start opens a PAM transaction for user. opts may be nil.
// The caller must Close the returned Transaction.
func Start(user string, opts *Options) (*Transaction, error) {
	initOnce.Do(initLibs)
	if initErr != nil {
		return nil, initErr
	}

	service := PamService
	if opts != nil && opts.Service != "" {
		service = opts.Service
	}

	// The pam_conv struct is saved by PAM and used throughout the
	// transaction lifetime (pam_authenticate etc. call back into it
	// internally). It must be allocated on the C heap; if a Go local
	// variable or Go heap allocation is used, the Go runtime may consider
	// it unreachable before the callback fires, causing PAM to access a
	// dangling pointer.
	convMem := cMalloc(unsafe.Sizeof(pamConv{}))
	if convMem == 0 {
		return nil, errors.New("failed to allocate memory for pam_conv")
	}

	t := &Transaction{convMem: convMem}
	convMu.Lock()
	t.id = convNextID
	convNextID++
	convTxns[t.id] = t
	convMu.Unlock()

	*(*pamConv)(cptr(convMem)) = pamConv{conv: convCallback, appData: t.id}

	var pamh uintptr
	if ret := pamStart(service, user, (*pamConv)(cptr(convMem)), &pamh); ret != pamSuccess {
		convMu.Lock()
		delete(convTxns, t.id)
		convMu.Unlock()
		cFree(convMem)
		return nil, fmt.Errorf("pam_start: %w", openpamError(ret))
	}
	t.pamh = pamh

	if opts != nil {
		items := [...]struct {
			typ int32
			val string
		}{
			{pamItemRHost, opts.RHost},
			{pamItemTTY, opts.TTY},
			{pamItemRUser, opts.RUser},
		}
		for _, it := range items {
			if it.val == "" {
				continue
			}
			if ret := pamSetItem(pamh, it.typ, it.val); ret != pamSuccess {
				t.Close()
				return nil, fmt.Errorf("pam_set_item: %w", openpamError(ret))
			}
		}
	}

	return t, nil
}

// do runs one pam_* primitive with the given conversation responder
// installed, and maps a non-success return code to a wrapped Error.
func (t *Transaction) do(name string, respond respondFunc, fn func() int32) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("pamtester: transaction already closed")
	}
	t.respond = respond
	defer func() { t.respond = nil }()

	ret := fn()
	t.lastStatus = ret
	if ret != pamSuccess {
		return fmt.Errorf("%s: %w", name, openpamError(ret))
	}
	return nil
}

// Authenticate verifies password via pam_authenticate. Returns nil if the
// password is correct; a wrong password yields an error matching ErrAuth
// (use errors.Is).
//
// The password is supplied through both channels a module may use: it is
// pre-set as the PAM_AUTHTOK item — macOS verification stacks like the
// default "checkpw" service pass use_first_pass to pam_opendirectory, which
// only reads that item and fails without ever calling the conversation — and
// the conversation answers any prompt with it for modules that do ask.
// (OpenPAM, unlike Linux-PAM, allows applications to set PAM_AUTHTOK.)
//
// Note that Authenticate only proves the password is right — call AcctMgmt
// afterwards to check that the account itself is still usable.
func (t *Transaction) Authenticate(password string) error {
	return t.do("pam_authenticate",
		func(style int32, prompt string) (string, bool) { return password, true },
		func() int32 {
			if ret := pamSetItem(t.pamh, pamItemAuthTok, password); ret != pamSuccess {
				return ret
			}
			return pamAuthenticate(t.pamh, 0)
		})
}

// AcctMgmt runs pam_acct_mgmt: it checks that the account is valid — not
// expired or locked, and access not denied by modules like pam_access or
// pam_time. A special case is an error matching ErrNewAuthTokReqd: the
// account is fine but the password has expired and must be changed (e.g. via
// ChangeAuthTok).
func (t *Transaction) AcctMgmt() error {
	return t.do("pam_acct_mgmt",
		nil, // informational messages are handled; actual prompts are unexpected here
		func() int32 { return pamAcctMgmt(t.pamh, 0) })
}

// ChangeAuthTok changes the user's password via pam_chauthtok.
//
// The default macOS service "checkpw" carries no password stack, so changing
// a password requires a service that does, e.g. Options{Service: "passwd"}
// (whose stack is `password required pam_opendirectory.so`).
//
// pam_opendirectory prompts "Old Password:" then "New Password:"; prompts
// containing "new" (case-insensitive) are answered with newPassword, anything
// else with oldPassword. Go programs never call setlocale(), so prompts stay
// untranslated C-locale English and this matching is reliable even when LANG
// is set.
//
// Failures (wrong oldPassword, or newPassword rejected by the directory's
// password policy) yield errors matching ErrAuthTok or ErrAuthTokRecovery
// depending on the module. Password updates go through OpenDirectory, so
// non-root users can change their own password.
func (t *Transaction) ChangeAuthTok(oldPassword, newPassword string) error {
	return t.do("pam_chauthtok",
		func(style int32, prompt string) (string, bool) {
			if strings.Contains(strings.ToLower(prompt), "new") {
				return newPassword, true
			}
			return oldPassword, true
		},
		func() int32 { return pamChauthtok(t.pamh, 0) })
}

// Close ends the transaction with pam_end and releases all resources.
// Calling Close more than once is harmless.
func (t *Transaction) Close() error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return nil
	}
	t.closed = true

	var err error
	if t.pamh != 0 {
		if ret := pamEnd(t.pamh, t.lastStatus); ret != pamSuccess {
			err = fmt.Errorf("pam_end: %w", Error(ret))
		}
		t.pamh = 0
	}

	convMu.Lock()
	delete(convTxns, t.id)
	convMu.Unlock()

	if t.convMem != 0 {
		cFree(t.convMem)
		t.convMem = 0
	}
	return err
}
