//go:build nopamtester || (!linux && !darwin && !windows)

package pamtester

import (
	"errors"
	"testing"
)

func TestStubUnsupported(t *testing.T) {
	if _, err := Start("root", nil); !errors.Is(err, errors.ErrUnsupported) {
		t.Fatalf("Start = %v, want errors.ErrUnsupported", err)
	}
}
