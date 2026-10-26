//go:build (linux || darwin) && !nopamtester

// Shared purego-based PAM backend for Linux-PAM (pam_linux.go) and OpenPAM
// (pam_darwin.go). The platform files provide the default service, library
// names and the translation of native return codes:
//
//	PamService                   default service name
//	libpamNames                  candidate libpam names for dlopen
//	pamError(ret) Error          native return code -> portable Error
//	nativeConvErr, nativeBufErr  native codes returned by the conversation
//	presetAuthTok                whether Authenticate also sets PAM_AUTHTOK

package pamtester

import (
	"errors"
	"fmt"
	"slices"
	"strings"
	"sync"
	"unicode"
	"unsafe"

	"github.com/ebitengine/purego"
)

// ---------- PAM constants common to Linux-PAM and OpenPAM ----------

const (
	pamSuccess = 0 // PAM_SUCCESS

	// pam_set_item item types
	pamItemUser    = 2 // PAM_USER
	pamItemTTY     = 3 // PAM_TTY
	pamItemRHost   = 4 // PAM_RHOST
	pamItemAuthTok = 6 // PAM_AUTHTOK
	pamItemRUser   = 8 // PAM_RUSER

	// flags, same values in Linux-PAM and OpenPAM
	pamDisallowNullAuthTok  = 0x1  // PAM_DISALLOW_NULL_AUTHTOK
	pamChangeExpiredAuthTok = 0x20 // PAM_CHANGE_EXPIRED_AUTHTOK
)

// ---------- C struct memory layouts ----------
//
// No explicit padding: Go aligns uintptr fields to the platform word size
// exactly like a C compiler does, so these match on 32- and 64-bit alike.

// struct pam_message { int msg_style; const char *msg; };
type pamMessage struct {
	msgStyle int32
	msg      uintptr
}

// struct pam_response { char *resp; int resp_retcode; };
type pamResponse struct {
	resp        uintptr
	respRetcode int32
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
	pamGetItem      func(pamh uintptr, itemType int32, item *uintptr) int32
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

	libpam, err := dlopenAny(libpamNames...)
	if err != nil {
		initErr = fmt.Errorf("failed to load libpam (PAM may not be installed): %w", err)
		return
	}

	purego.RegisterLibFunc(&pamStart, libpam, "pam_start")
	purego.RegisterLibFunc(&pamAuthenticate, libpam, "pam_authenticate")
	purego.RegisterLibFunc(&pamAcctMgmt, libpam, "pam_acct_mgmt")
	purego.RegisterLibFunc(&pamChauthtok, libpam, "pam_chauthtok")
	purego.RegisterLibFunc(&pamSetItem, libpam, "pam_set_item")
	purego.RegisterLibFunc(&pamGetItem, libpam, "pam_get_item")
	purego.RegisterLibFunc(&pamEnd, libpam, "pam_end")

	// Resolve the libc functions through the global symbol scope rather than
	// a separate dlopen of libc: memory handed to PAM is released with
	// whatever free() libpam binds to, so malloc/strdup must come from the
	// same allocator — which differs from libc's own when one such as
	// jemalloc or tcmalloc is LD_PRELOADed. libc itself is always loaded
	// (purego binaries link it), so these lookups cannot miss.
	purego.RegisterLibFunc(&cMalloc, purego.RTLD_DEFAULT, "malloc")
	purego.RegisterLibFunc(&cFree, purego.RTLD_DEFAULT, "free")
	purego.RegisterLibFunc(&cStrdup, purego.RTLD_DEFAULT, "strdup")
	purego.RegisterLibFunc(&cStrlen, purego.RTLD_DEFAULT, "strlen")

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
		return nativeConvErr
	}
	if numMsg <= 0 {
		return pamSuccess
	}
	n := int(numMsg)

	// msgs is `const struct pam_message **`, i.e. an array of n pointers
	msgPtrs := unsafe.Slice((*uintptr)(cptr(msgs)), n)

	respArray := cMalloc(uintptr(n) * unsafe.Sizeof(pamResponse{}))
	if respArray == 0 {
		return nativeBufErr
	}
	responses := unsafe.Slice((*pamResponse)(cptr(respArray)), n)
	for i := range responses {
		responses[i] = pamResponse{}
	}

	// release frees the responses and returns code; used on failure, and
	// when there is nowhere to hand them back to (respOut is NULL).
	release := func(code int32) int32 {
		for i := range responses {
			if responses[i].resp != 0 {
				cFree(responses[i].resp)
			}
		}
		cFree(respArray)
		return code
	}

	// t.respond, t.msgs and t.convErr are only touched here and in do, while
	// t.mu is held for the duration of the pam_* call — no extra locking.
	for i := 0; i < n; i++ {
		m := (*pamMessage)(cptr(msgPtrs[i]))
		style, text := Style(m.msgStyle), goString(m.msg)
		switch style {
		case PromptEchoOff, PromptEchoOn:
			if respOut == 0 || t.respond == nil {
				return release(nativeConvErr)
			}
			reply, err := t.respond(style, text)
			if err == nil {
				err = checkNUL(reply)
			}
			if err != nil {
				t.convErr = err
				return release(nativeConvErr)
			}
			if responses[i].resp = cStrdup(reply); responses[i].resp == 0 {
				return release(nativeBufErr)
			}
		case ErrorMsg, TextInfo:
			// No response expected; resp stays NULL. Keep the text (e.g.
			// "BAD PASSWORD: ..." or "Password will expire in 3 days")
			// so callers can see why an operation failed.
			t.msgs = append(t.msgs, text)
			if t.respond != nil {
				if _, err := t.respond(style, text); err != nil {
					t.convErr = err
					return release(nativeConvErr)
				}
			}
		}
	}

	// Some modules (e.g. pam_matrix's verbose messages) pass a NULL resp
	// pointer when sending only PAM_ERROR_MSG / PAM_TEXT_INFO.
	if respOut == 0 {
		return release(pamSuccess)
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
	respond    ConvFunc
	convErr    error    // error returned by respond during the last operation
	msgs       []string // PAM_ERROR_MSG / PAM_TEXT_INFO texts of the last operation
	lastStatus int32
	flags      int32 // flags for pam_authenticate / pam_acct_mgmt
	allowNull  bool  // Options.AllowNullAuthTok
	expired    bool  // last AcctMgmt reported ErrNewAuthTokReqd
	closed     bool
}

// Start opens a PAM transaction for user. If user is empty the current
// process user is used. opts may be nil. The caller must Close the returned
// Transaction.
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

	service := PamService
	if opts != nil && opts.Service != "" {
		service = opts.Service
	}
	if err := checkNUL(service, user); err != nil {
		return nil, err
	}
	if opts != nil {
		if err := checkNUL(opts.RHost, opts.TTY, opts.RUser); err != nil {
			return nil, err
		}
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

	t := &Transaction{convMem: convMem, flags: pamDisallowNullAuthTok}
	if opts != nil && opts.AllowNullAuthTok {
		t.flags, t.allowNull = 0, true
	}
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
		return nil, fmt.Errorf("pam_start: %w", pamError(ret))
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
				return nil, fmt.Errorf("pam_set_item: %w", pamError(ret))
			}
		}
	}

	return t, nil
}

// do runs one pam_* primitive with the given conversation responder
// installed, and maps a non-success return code to a wrapped Error.
func (t *Transaction) do(name string, respond ConvFunc, fn func() int32) error {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return errors.New("pamtester: transaction already closed")
	}
	t.respond = respond
	defer func() { t.respond = nil }()
	t.msgs, t.convErr = nil, nil

	ret := fn()
	t.lastStatus = ret
	if ret != pamSuccess {
		err := fmt.Errorf("%s: %w", name, pamError(ret))
		if len(t.msgs) > 0 {
			err = fmt.Errorf("%w (%s)", err, strings.Join(t.msgs, "; "))
		}
		if t.convErr != nil {
			err = fmt.Errorf("%w: %w", err, t.convErr)
		}
		return err
	}
	return nil
}

// User returns the PAM_USER item: the user name as the PAM modules see it.
// Modules may rewrite it — e.g. case folding, alias or Kerberos principal
// mapping, or a username prompt — so after a successful Authenticate this
// is the account that was actually checked, which may differ from the name
// given to Start.
func (t *Transaction) User() (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()
	if t.closed {
		return "", errors.New("pamtester: transaction already closed")
	}
	var p uintptr
	if ret := pamGetItem(t.pamh, pamItemUser, &p); ret != pamSuccess {
		return "", fmt.Errorf("pam_get_item: %w", pamError(ret))
	}
	return goString(p), nil
}

// Messages returns the error and informational messages (PAM_ERROR_MSG /
// PAM_TEXT_INFO) that PAM modules emitted during the most recent
// Authenticate, AcctMgmt or ChangeAuthTok call — e.g. why a new password was
// rejected, or that the password is about to expire. They are also appended
// to the text of the error returned by a failed call.
func (t *Transaction) Messages() []string {
	t.mu.Lock()
	defer t.mu.Unlock()
	return append([]string(nil), t.msgs...)
}

// Authenticate verifies password via pam_authenticate. Returns nil if the
// password is correct; a wrong password yields an error matching ErrAuth
// (use errors.Is).
//
// Regardless of what the PAM module asks (typically "Password:"), the
// conversation responds uniformly with the given password. On macOS the
// password is additionally pre-set as the PAM_AUTHTOK item: verification
// stacks like the default "checkpw" service pass use_first_pass to
// pam_opendirectory, which only reads that item and fails without ever
// calling the conversation. (OpenPAM, unlike Linux-PAM, allows applications
// to set PAM_AUTHTOK.)
//
// An empty password is rejected with ErrAuth unless Options.AllowNullAuthTok
// is set.
//
// Note that Authenticate only proves the password is right — call AcctMgmt
// afterwards to check that the account itself is still usable.
func (t *Transaction) Authenticate(password string) error {
	if err := checkNUL(password); err != nil {
		return err
	}
	if password == "" && !t.allowNull {
		return errNullAuthTok
	}
	return t.do("pam_authenticate",
		func(Style, string) (string, error) { return password, nil },
		func() int32 {
			if presetAuthTok {
				if ret := pamSetItem(t.pamh, pamItemAuthTok, password); ret != pamSuccess {
					return ret
				}
			}
			return pamAuthenticate(t.pamh, t.flags)
		})
}

// AuthenticateConv runs pam_authenticate with conv answering every
// conversation message, for stacks that ask more than a single password —
// e.g. a password followed by an OTP, or a username prompt. Error and info
// messages are passed to conv as well, and are also kept for Messages.
//
// Unlike Authenticate, nothing is pre-set as PAM_AUTHTOK, so on macOS use a
// service whose modules prompt (not the default "checkpw", whose
// pam_opendirectory runs with use_first_pass). PAM_DISALLOW_NULL_AUTHTOK is
// still passed unless Options.AllowNullAuthTok is set.
func (t *Transaction) AuthenticateConv(conv ConvFunc) error {
	if conv == nil {
		return errors.New("pamtester: nil ConvFunc")
	}
	return t.do("pam_authenticate", conv,
		func() int32 { return pamAuthenticate(t.pamh, t.flags) })
}

// AcctMgmt runs pam_acct_mgmt: it checks that the account is valid — not
// expired or locked, and access not denied by modules like pam_access or
// pam_time. A special case is an error matching ErrNewAuthTokReqd: the
// account is fine but the password has expired and must be changed (e.g. via
// ChangeAuthTok).
func (t *Transaction) AcctMgmt() error {
	return t.do("pam_acct_mgmt",
		nil, // informational messages are handled; actual prompts are unexpected here
		func() int32 {
			ret := pamAcctMgmt(t.pamh, t.flags)
			t.expired = ret != pamSuccess && pamError(ret) == ErrNewAuthTokReqd
			return ret
		})
}

// ChangeAuthTok changes the user's password via pam_chauthtok. Each prompt
// is classified by passwordPromptIsNew: prompts for the current/old password
// get oldPassword, prompts for the new password or its confirmation get
// newPassword, and an unrecognised prompt gets oldPassword (or newPassword
// when oldPassword is empty, as when root changes a password). Go programs
// never call setlocale(), so libpam prompts stay untranslated C-locale
// English and this matching is reliable even when LANG is set. For stacks
// whose prompts do not fit, use ChangeAuthTokConv.
//
// If AcctMgmt on this transaction reported ErrNewAuthTokReqd, the change is
// made with PAM_CHANGE_EXPIRED_AUTHTOK — as login(1) and sshd do — so
// modules only update the expired token.
//
// Failures (wrong oldPassword, newPassword rejected by quality checks or
// password policy, or no permission to update the password store) yield
// errors matching ErrAuthTok or ErrAuthTokRecovery depending on the module.
//
// Linux: without root privileges pam_unix first asks for the current
// password ("Current password:"), then for the new one twice; as root the
// old password is usually not requested and oldPassword may be empty.
// Actually updating the password requires write access to /etc/shadow: root
// always works, while non-root only works on systems whose pam_unix ships a
// setuid unix_update helper (e.g. RHEL; Debian/Ubuntu do not — there the
// passwd(1) command relies on its own setuid bit).
//
// macOS: the default service "checkpw" carries no password stack, so use a
// service that does, e.g. Options{Service: "passwd"} (whose stack is
// `password required pam_opendirectory.so`). pam_opendirectory prompts
// "Old Password:" then "New Password:". Updates go through OpenDirectory, so
// non-root users can change their own password.
func (t *Transaction) ChangeAuthTok(oldPassword, newPassword string) error {
	if err := checkNUL(oldPassword, newPassword); err != nil {
		return err
	}
	return t.do("pam_chauthtok",
		func(_ Style, prompt string) (string, error) {
			if passwordPromptIsNew(prompt, oldPassword == "") {
				return newPassword, nil
			}
			return oldPassword, nil
		},
		t.chauthtok)
}

// chauthtok calls pam_chauthtok, adding PAM_CHANGE_EXPIRED_AUTHTOK when the
// last AcctMgmt found the password expired. Runs under t.mu via do.
func (t *Transaction) chauthtok() int32 {
	var flags int32
	if t.expired {
		flags |= pamChangeExpiredAuthTok
	}
	ret := pamChauthtok(t.pamh, flags)
	if ret == pamSuccess {
		t.expired = false
	}
	return ret
}

// passwordPromptIsNew reports whether a pam_chauthtok prompt asks for the
// new password (or its confirmation) rather than the current one. It looks
// at whole words, so "(current) UNIX password:", "Old Password:", "New
// password:", "Retype new password:", "Reenter new Password:" and "Enter it
// again:" are all recognised. Prompts mentioning neither kind fall back to
// fallbackNew.
func passwordPromptIsNew(prompt string, fallbackNew bool) bool {
	words := strings.FieldsFunc(strings.ToLower(prompt), func(r rune) bool {
		return !unicode.IsLetter(r)
	})
	has := func(w string) bool { return slices.Contains(words, w) }
	switch {
	case has("current") || has("old") || has("existing"):
		return false
	case has("new") || has("again") || has("retype") || has("reenter") ||
		has("repeat") || has("confirm") ||
		has("re") && (has("enter") || has("type")):
		return true
	}
	return fallbackNew
}

// ChangeAuthTokConv runs pam_chauthtok with conv answering every
// conversation message, for callers that want to drive the password change
// interactively or handle prompts ChangeAuthTok does not recognise.
func (t *Transaction) ChangeAuthTokConv(conv ConvFunc) error {
	if conv == nil {
		return errors.New("pamtester: nil ConvFunc")
	}
	return t.do("pam_chauthtok", conv,
		t.chauthtok)
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
			err = fmt.Errorf("pam_end: %w", pamError(ret))
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
