package pamtester

import (
	"errors"
	"fmt"
	"strings"
	"testing"
)

func TestErrorString(t *testing.T) {
	for e := ErrOpen; e <= ErrIncomplete; e++ {
		if s := e.Error(); strings.HasPrefix(s, "PAM error ") {
			t.Errorf("Error(%d) has no message: %q", int32(e), s)
		}
	}
	if got, want := Error(99).Error(), "PAM error 99"; got != want {
		t.Errorf("Error(99) = %q, want %q", got, want)
	}
}

func TestErrorIs(t *testing.T) {
	err := fmt.Errorf("pam_authenticate: %w", ErrAuth)
	if !errors.Is(err, ErrAuth) {
		t.Error("errors.Is(wrapped ErrAuth, ErrAuth) = false")
	}
	if errors.Is(err, ErrUserUnknown) {
		t.Error("errors.Is(wrapped ErrAuth, ErrUserUnknown) = true")
	}
}

func TestCheckNUL(t *testing.T) {
	if err := checkNUL("", "user", "pass word"); err != nil {
		t.Errorf("checkNUL(valid) = %v", err)
	}
	if err := checkNUL("ok", "sec\x00ret"); err != errNUL {
		t.Errorf("checkNUL(with NUL) = %v, want errNUL", err)
	}
}

func TestStartRejectsNUL(t *testing.T) {
	if _, err := Start("ro\x00ot", nil); err == nil {
		t.Fatal(`Start("ro\x00ot") succeeded`)
	}
}
