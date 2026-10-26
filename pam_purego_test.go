//go:build (linux || darwin || (freebsd && cgo)) && !nopamtester

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

func TestPasswordPromptIsNew(t *testing.T) {
	for _, c := range []struct {
		prompt      string
		fallbackNew bool
		want        bool
	}{
		// pam_unix
		{"Current password: ", false, false},
		{"(current) UNIX password: ", false, false},
		{"New password: ", false, true},
		{"Retype new password: ", false, true},
		{"Enter new UNIX password: ", false, true},
		// pam_opendirectory
		{"Old Password:", false, false},
		{"New Password:", false, true},
		// sssd
		{"Current Password: ", false, false},
		{"Reenter new Password: ", false, true},
		// others
		{"Re-enter password: ", false, true},
		{"Re-type password: ", false, true},
		{"Enter it again: ", false, true},
		{"Confirm password: ", false, true},
		{"Renewal code: ", false, false}, // "renewal" is not the word "new"
		// unrecognised: fall back
		{"Password for alice@EXAMPLE.COM: ", false, false},
		{"Password: ", true, true},
	} {
		if got := passwordPromptIsNew(c.prompt, c.fallbackNew); got != c.want {
			t.Errorf("passwordPromptIsNew(%q, %v) = %v, want %v", c.prompt, c.fallbackNew, got, c.want)
		}
	}
}
