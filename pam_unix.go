//go:build linux

// Package pamtester verifies a user's login password by calling the system's
// libpam directly via purego (no cgo required).
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
//	  3. pam_end()            Closes the transaction.
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
//
package pamtester

import (
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"github.com/ebitengine/purego"
)

// ---------- PAM constants (from <security/_pam_types.h>) ----------

const (
	pamSuccess = 0 // PAM_SUCCESS
	pamBufErr  = 5 // PAM_BUF_ERR

	pamPromptEchoOff = 1 // prompt for input without echo — typical "Password:" prompt
	pamPromptEchoOn  = 2 // prompt for input with echo
)

// PamService specifies the PAM service configuration file under /etc/pam.d/.
// "passwd" exists on almost all distributions and carries the semantics of
// "verify/change the current user's password". Unlike "login", it does not
// impose extra restrictions such as securetty or allowed login time windows.
// If the target system lacks this file, alternatives like "login" or "su" can
// be used, or a minimal PAM service file can be created (typically just
// `auth required pam_unix.so`).
var PamService = "passwd"

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
	pamEnd          func(pamh uintptr, status int32) int32
	pamStrerror     func(pamh uintptr, errnum int32) string

	cMalloc func(size uintptr) uintptr
	cFree   func(ptr uintptr)
	cStrdup func(s string) uintptr
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

	libpam, err := dlopenAny("libpam.so.0", "libpam.so")
	if err != nil {
		initErr = fmt.Errorf("failed to load libpam (PAM may not be installed): %w", err)
		return
	}
	libc, err := dlopenAny("libc.so.6", "libc.so")
	if err != nil {
		initErr = fmt.Errorf("failed to load libc: %w", err)
		return
	}

	purego.RegisterLibFunc(&pamStart, libpam, "pam_start")
	purego.RegisterLibFunc(&pamAuthenticate, libpam, "pam_authenticate")
	purego.RegisterLibFunc(&pamEnd, libpam, "pam_end")
	purego.RegisterLibFunc(&pamStrerror, libpam, "pam_strerror")

	purego.RegisterLibFunc(&cMalloc, libc, "malloc")
	purego.RegisterLibFunc(&cFree, libc, "free")
	purego.RegisterLibFunc(&cStrdup, libc, "strdup")
}

// buildConvCallback constructs a PAM conversation function callable from C:
// regardless of what the PAM module asks (typically "Password:"), it responds
// uniformly with the given password.
//
// The returned respArray and each resp string must be allocated with C's
// malloc/strdup — PAM will free them itself when done. Using Go-allocated
// memory here would cause PAM to attempt freeing an address not managed by
// libc, resulting in a crash.
func buildConvCallback(password string) uintptr {
	return purego.NewCallback(func(numMsg int32, msgs uintptr, respOut uintptr, _ uintptr) int32 {
		if numMsg <= 0 {
			return pamSuccess
		}
		n := int(numMsg)

		// msgs is `const struct pam_message **`, i.e. an array of n pointers
		msgPtrs := unsafe.Slice((*uintptr)(unsafe.Pointer(msgs)), n)

		respArray := cMalloc(uintptr(n) * unsafe.Sizeof(pamResponse{}))
		if respArray == 0 {
			return pamBufErr
		}
		responses := unsafe.Slice((*pamResponse)(unsafe.Pointer(respArray)), n)

		for i := 0; i < n; i++ {
			responses[i] = pamResponse{}
			m := (*pamMessage)(unsafe.Pointer(msgPtrs[i]))
			if m.msgStyle == pamPromptEchoOff || m.msgStyle == pamPromptEchoOn {
				responses[i].resp = cStrdup(password)
			}
			// PAM_ERROR_MSG / PAM_TEXT_INFO messages need no response; resp stays NULL
		}

		*(*uintptr)(unsafe.Pointer(respOut)) = respArray
		return pamSuccess
	})
}

// CheckUserPassword verifies whether password is the login password for the
// given user. Returns nil if the password is correct; returns a non-nil error
// if the password is wrong, the user does not exist, or the PAM environment is
// misconfigured.
func CheckUserPassword(user, password string) error {
	initOnce.Do(initLibs)
	if initErr != nil {
		return initErr
	}

	// The pam_conv address is saved by PAM and used throughout the
	// transaction lifetime (pam_authenticate calls back into it
	// internally). It must be allocated on the C heap; if a Go local
	// variable or Go heap allocation is used, the Go runtime may consider
	// it unreachable before the callback fires, causing PAM to access a
	// dangling pointer.
	convMem := cMalloc(unsafe.Sizeof(pamConv{}))
	if convMem == 0 {
		return errors.New("failed to allocate memory for pam_conv")
	}
	defer cFree(convMem)
	*(*pamConv)(unsafe.Pointer(convMem)) = pamConv{
		conv: buildConvCallback(password),
	}

	var pamh uintptr
	if ret := pamStart(PamService, user, (*pamConv)(unsafe.Pointer(convMem)), &pamh); ret != pamSuccess {
		return fmt.Errorf("pam_start failed, code=%d", ret)
	}

	ret := pamAuthenticate(pamh, 0)
	defer pamEnd(pamh, ret)

	if ret != pamSuccess {
		return fmt.Errorf("password authentication failed: %s", pamStrerror(pamh, ret))
	}
	return nil
}
