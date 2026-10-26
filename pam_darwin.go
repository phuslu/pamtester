//go:build darwin && !nopamtester

package pamtester

// PamService is the default PAM service configuration file under /etc/pam.d/,
// used when Options.Service is empty.
var PamService = "checkpw"

var libpamNames = []string{"libpam.2.dylib", "libpam.dylib"}

// macOS ships OpenPAM, whose return codes (<security/pam_constants.h>) are
// numbered differently from Linux-PAM (e.g. PAM_AUTH_ERR is 9 here but 7 on
// Linux). Native codes are therefore translated to the portable Error
// constants via pamError before being surfaced, and the conversation
// callback returns native codes.
const (
	nativeBufErr  = 5 // PAM_BUF_ERR
	nativeConvErr = 6 // PAM_CONV_ERR

	// pam_opendirectory with use_first_pass only reads PAM_AUTHTOK, which
	// OpenPAM lets applications set; see Authenticate.
	presetAuthTok = true

	pamChangeExpiredAuthTok = 0x4 // PAM_CHANGE_EXPIRED_AUTHTOK (0x20 in Linux-PAM)
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
	31: ErrBadItem,             // PAM_BAD_ITEM (OpenPAM extension)
}

func pamError(ret int32) Error {
	if int(ret) < len(openpamErrors) && openpamErrors[ret] != 0 {
		return openpamErrors[ret]
	}
	// PAM_DOMAIN_UNKNOWN, the other OpenPAM extensions (PAM_BAD_HANDLE,
	// PAM_BAD_FEATURE, PAM_BAD_CONSTANT) and anything newer have no portable
	// equivalent
	return ErrSystem
}
