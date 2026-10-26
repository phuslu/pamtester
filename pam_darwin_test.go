//go:build darwin && !nopamtester

package pamtester

import (
	"errors"
	"os"
	"testing"
)

func TestOpenPAMErrorMapping(t *testing.T) {
	for _, c := range []struct {
		native int32
		want   Error
	}{
		{6, ErrConv},
		{9, ErrAuth},
		{10, ErrNewAuthTokReqd},
		{13, ErrUserUnknown},
		{20, ErrAuthTok},
		{21, ErrAuthTokRecovery},
		{28, ErrModuleUnknown},
		{29, ErrSystem}, // PAM_DOMAIN_UNKNOWN has no portable equivalent
		{1000, ErrSystem},
	} {
		if got := pamError(c.native); got != c.want {
			t.Errorf("pamError(%d) = %v, want %v", c.native, got, c.want)
		}
	}
	if nativeConvErr != 6 || nativeBufErr != 5 {
		t.Errorf("native conv/buf codes = %d/%d, want 6/5", nativeConvErr, nativeBufErr)
	}
}

// TestAuthenticateWrongPassword runs against the real checkpw service: a
// bogus password for the current user must fail with ErrAuth.
func TestAuthenticateWrongPassword(t *testing.T) {
	if os.Getenv("PAMTESTER_LIVE") == "" {
		t.Skip("set PAMTESTER_LIVE=1 to run against the real account database (records one failed logon)")
	}
	tx, err := Start("", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	if err := tx.Authenticate("pamtester-definitely-wrong-password"); !errors.Is(err, ErrAuth) {
		t.Fatalf("Authenticate(wrong) = %v, want ErrAuth", err)
	}
}
