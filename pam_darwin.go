//go:build darwin && !nopamtester

package pamtester

// PamService is the default PAM service configuration file under /etc/pam.d/,
// used when Options.Service is empty.
var PamService = "checkpw"

var libpamNames = []string{"libpam.2.dylib", "libpam.dylib"}

// pam_opendirectory with use_first_pass only reads PAM_AUTHTOK, which
// OpenPAM lets applications set; see Authenticate.
const presetAuthTok = true
