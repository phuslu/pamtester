//go:build freebsd && cgo && !nopamtester

package pamtester

// The FreeBSD backend needs cgo: purego's fakecgo on FreeBSD only builds
// with CGO_ENABLED=0 given a special -gcflags flag, so cgo-less builds
// (e.g. cross-compiles) fall back to the stub in pam_zzz.go instead.

// PamService is the default PAM service configuration file under /etc/pam.d/,
// used when Options.Service is empty. FreeBSD's "system" stack runs pam_unix
// for auth, account and password, whereas its "passwd" stack only defines
// the password facility.
var PamService = "system"

var libpamNames = []string{"libpam.so.6", "libpam.so"}

// pam_unix runs with try_first_pass and prompts through the conversation
// when PAM_AUTHTOK is unset, so there is no need to pre-set it.
const presetAuthTok = false
