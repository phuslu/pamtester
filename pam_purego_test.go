//go:build (linux || darwin) && !nopamtester

package pamtester

import (
	"testing"
	"unsafe"
)

// TestCStructLayout checks the Go mirrors of the PAM structs against the C
// layout on the current GOARCH: an int followed by a pointer, a pointer
// followed by an int, and two pointers.
func TestCStructLayout(t *testing.T) {
	ptr := unsafe.Sizeof(uintptr(0))
	checks := []struct {
		name      string
		got, want uintptr
	}{
		{"offsetof(pam_message.msg)", unsafe.Offsetof(pamMessage{}.msg), ptr},
		{"sizeof(pam_message)", unsafe.Sizeof(pamMessage{}), 2 * ptr},
		{"offsetof(pam_response.resp_retcode)", unsafe.Offsetof(pamResponse{}.respRetcode), ptr},
		{"sizeof(pam_response)", unsafe.Sizeof(pamResponse{}), 2 * ptr},
		{"sizeof(pam_conv)", unsafe.Sizeof(pamConv{}), 2 * ptr},
	}
	for _, c := range checks {
		if c.got != c.want {
			t.Errorf("%s = %d, want %d", c.name, c.got, c.want)
		}
	}
}
