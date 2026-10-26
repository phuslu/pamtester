//go:build windows && !nopamtester

package pamtester

import (
	"errors"
	"os"
	"syscall"
	"testing"
)

func TestWinErrorMapping(t *testing.T) {
	for _, c := range []struct {
		code uint32
		want Error
	}{
		{1326, ErrAuth},
		{1330, ErrNewAuthTokReqd},
		{1907, ErrNewAuthTokReqd},
		{1331, ErrAcctExpired},
		{1909, ErrMaxTries},
		{2221, ErrUserUnknown},
		{2245, ErrAuthTok},
		{86, ErrAuthTokRecovery},
		{2226, ErrSystem}, // NERR_NotPrimary
		{12345, ErrSystem},
	} {
		if got := mapWinError(c.code); got != c.want {
			t.Errorf("mapWinError(%d) = %v, want %v", c.code, got, c.want)
		}
	}

	err := winError(1326)
	if !errors.Is(err, ErrAuth) {
		t.Errorf("winError(1326) does not match ErrAuth: %v", err)
	}
	if !errors.Is(err, syscall.Errno(1326)) {
		t.Errorf("winError(1326) does not match syscall.Errno(1326): %v", err)
	}
}

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
