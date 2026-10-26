//go:build linux && !nopamtester

package pamtester

// PamService is the default PAM service configuration file under /etc/pam.d/,
// used when Options.Service is empty.
//
// On many distributions /etc/pam.d/passwd only defines a "password" stack.
// Authenticate and AcctMgmt then work only because Linux-PAM falls back,
// per module type, to /etc/pam.d/other — on Debian/Ubuntu that includes
// common-auth/common-account, but distributions whose "other" stack is
// pam_deny reject every authentication. Services that mainly verify
// passwords should set Options.Service to a stack with an "auth" section
// (e.g. "login", "system-auth", or a dedicated file for the application).
var PamService = "passwd"

var (
	libpamNames = []string{"libpam.so.0", "libpam.so"}
	libcNames   = []string{"libc.so.6", "libc.so"}
)

// Linux-PAM numbering is what Error uses, so native codes need no
// translation.
const (
	nativeConvErr = int32(ErrConv)
	nativeBufErr  = int32(ErrBuf)

	// Linux-PAM refuses PAM_AUTHTOK from applications (PAM_BAD_ITEM); the
	// password is supplied through the conversation only.
	presetAuthTok = false
)

func pamError(ret int32) Error {
	return Error(ret)
}
