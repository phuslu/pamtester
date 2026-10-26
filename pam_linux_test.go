//go:build linux && !nopamtester

package pamtester

// Integration tests against a real libpam, sandboxed with cwrap's
// pam_wrapper (Debian/Ubuntu package libpam-wrapper): pam_wrapper redirects
// the service directory, and its pam_matrix module authenticates against a
// plain-text passdb, so no real accounts or root are involved.
//
// pam_wrapper reads its configuration from the C environment at load time,
// which os.Setenv in a cgo-less binary does not reach. TestMain therefore
// prepares a sandbox and re-executes the test binary with the environment
// set. Without libpam_wrapper the tests are skipped, unless
// PAMTESTER_REQUIRE_PAM_WRAPPER is set (as in CI).

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

const (
	envWrapped     = "PAMTESTER_PAM_WRAPPED"
	envWrapperLib  = "PAMTESTER_PAM_WRAPPER_LIB"
	envRequireWrap = "PAMTESTER_REQUIRE_PAM_WRAPPER"

	testUser     = "alice"
	testPassword = "s3cret"
)

var wrapperSkipReason string

func findPamWrapper() string {
	if p := os.Getenv(envWrapperLib); p != "" {
		return p
	}
	for _, pattern := range []string{
		"/usr/lib/*/libpam_wrapper.so",
		"/usr/lib64/libpam_wrapper.so",
		"/usr/lib/libpam_wrapper.so",
	} {
		if m, _ := filepath.Glob(pattern); len(m) > 0 {
			return m[0]
		}
	}
	return ""
}

func TestMain(m *testing.M) {
	if os.Getenv(envWrapped) != "" {
		libpamNames = []string{os.Getenv(envWrapperLib)}
		os.Exit(m.Run())
	}

	lib := findPamWrapper()
	if lib == "" {
		if os.Getenv(envRequireWrap) != "" {
			fmt.Fprintln(os.Stderr, "libpam_wrapper.so not found but", envRequireWrap, "is set")
			os.Exit(1)
		}
		wrapperSkipReason = "libpam_wrapper.so not found (install libpam-wrapper or set " + envWrapperLib + ")"
		os.Exit(m.Run())
	}
	os.Exit(runWrapped(m, lib))
}

// runWrapped writes the pam_wrapper service directory and passdb into a
// temporary directory and re-runs the test binary inside that sandbox.
func runWrapped(m *testing.M, lib string) int {
	dir, err := os.MkdirTemp("", "pamtester-test-")
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	defer os.RemoveAll(dir)

	modDir := filepath.Join(filepath.Dir(lib), "pam_wrapper")
	matrix := filepath.Join(modDir, "pam_matrix.so")
	chatty := filepath.Join(modDir, "pam_chatty.so")
	passdb := filepath.Join(dir, "passdb")

	files := map[string]string{
		"passdb": fmt.Sprintf("%s:%s:matrix\n", testUser, testPassword),
		"services/matrix": fmt.Sprintf(
			"auth required %[1]s passdb=%[2]s\naccount required %[1]s passdb=%[2]s\npassword required %[1]s passdb=%[2]s\n",
			matrix, passdb),
		"services/verbose": fmt.Sprintf(
			"auth required %[1]s passdb=%[2]s verbose\naccount required %[1]s passdb=%[2]s verbose\npassword required %[1]s passdb=%[2]s verbose\n",
			matrix, passdb),
		"services/chatty": fmt.Sprintf("auth required %s num_lines=2 info error\n", chatty),
	}
	for name, content := range files {
		p := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err == nil {
			err = os.WriteFile(p, []byte(content), 0o600)
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			return 1
		}
	}

	cmd := exec.Command(os.Args[0], os.Args[1:]...)
	cmd.Stdout, cmd.Stderr = os.Stdout, os.Stderr
	cmd.Env = append(os.Environ(),
		envWrapped+"=1",
		envWrapperLib+"="+lib,
		"PAM_WRAPPER=1",
		"PAM_WRAPPER_SERVICE_DIR="+filepath.Join(dir, "services"),
	)
	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode()
		}
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	return 0
}

func startMatrix(t *testing.T, service string) *Transaction {
	t.Helper()
	if wrapperSkipReason != "" {
		t.Skip(wrapperSkipReason)
	}
	tx, err := Start(testUser, &Options{Service: service, RHost: "192.0.2.1", TTY: "pts/0", RUser: "bob"})
	if err != nil {
		t.Fatalf("Start: %v", err)
	}
	t.Cleanup(func() { tx.Close() })
	return tx
}

func TestWrapperAuthenticate(t *testing.T) {
	tx := startMatrix(t, "matrix")
	if err := tx.Authenticate(testPassword); err != nil {
		t.Fatalf("Authenticate(correct) = %v", err)
	}
	if err := tx.AcctMgmt(); err != nil {
		t.Fatalf("AcctMgmt = %v", err)
	}
}

func TestWrapperAuthenticateWrongPassword(t *testing.T) {
	tx := startMatrix(t, "matrix")
	if err := tx.Authenticate("wrong"); !errors.Is(err, ErrAuth) {
		t.Fatalf("Authenticate(wrong) = %v, want ErrAuth", err)
	}
	// a prefix of the right password followed by NUL must not pass
	if err := tx.Authenticate(testPassword + "\x00junk"); err != errNUL {
		t.Fatalf("Authenticate(password+NUL) = %v, want errNUL", err)
	}
}

func TestWrapperAcctMgmtWrongService(t *testing.T) {
	// pam_matrix's account module only admits a user for the service named
	// in the passdb; alice is listed for "matrix", not "verbose".
	tx := startMatrix(t, "verbose")
	if err := tx.Authenticate(testPassword); err != nil {
		t.Fatalf("Authenticate = %v", err)
	}
	if err := tx.AcctMgmt(); err == nil {
		t.Fatal("AcctMgmt for a service the user is not allowed on succeeded")
	}
}

func TestWrapperMessages(t *testing.T) {
	tx := startMatrix(t, "verbose")
	err := tx.Authenticate("wrong")
	if !errors.Is(err, ErrAuth) {
		t.Fatalf("Authenticate(wrong) = %v, want ErrAuth", err)
	}
	msgs := tx.Messages()
	if len(msgs) == 0 {
		t.Fatal("Messages() is empty after a verbose failure")
	}
	if !strings.Contains(err.Error(), msgs[0]) {
		t.Errorf("error %q does not include message %q", err, msgs[0])
	}

	if err := tx.Authenticate(testPassword); err != nil {
		t.Fatalf("Authenticate(correct) = %v", err)
	}
	for _, m := range tx.Messages() {
		if m == msgs[0] {
			t.Errorf("Messages() still holds %q from the previous call", m)
		}
	}
}

func TestWrapperChattyMessages(t *testing.T) {
	tx := startMatrix(t, "chatty")
	if err := tx.Authenticate("anything"); err != nil {
		t.Fatalf("Authenticate = %v", err)
	}
	// num_lines=2 of both info and error; some pam_chatty versions emit
	// one extra line per kind, so only require the minimum.
	if got := len(tx.Messages()); got < 4 {
		t.Errorf("len(Messages()) = %d, want >= 4: %q", got, tx.Messages())
	}
}

func TestWrapperChangeAuthTok(t *testing.T) {
	const newPassword = "n3w-Secret!"

	tx := startMatrix(t, "matrix")
	if err := tx.ChangeAuthTok(testPassword, newPassword); err != nil {
		t.Fatalf("ChangeAuthTok = %v", err)
	}
	t.Cleanup(func() {
		tx := startMatrix(t, "matrix")
		if err := tx.ChangeAuthTok(newPassword, testPassword); err != nil {
			t.Errorf("restoring password: %v", err)
		}
	})

	tx2 := startMatrix(t, "matrix")
	if err := tx2.Authenticate(testPassword); !errors.Is(err, ErrAuth) {
		t.Errorf("Authenticate(old) after change = %v, want ErrAuth", err)
	}
	if err := tx2.Authenticate(newPassword); err != nil {
		t.Errorf("Authenticate(new) after change = %v", err)
	}
}

func TestWrapperUnknownService(t *testing.T) {
	if wrapperSkipReason != "" {
		t.Skip(wrapperSkipReason)
	}
	tx, err := Start(testUser, &Options{Service: "does-not-exist"})
	if err != nil {
		return // rejected at pam_start: fine
	}
	defer tx.Close()
	if err := tx.Authenticate(testPassword); err == nil {
		t.Fatal("Authenticate on a nonexistent service succeeded")
	}
}

func TestWrapperClose(t *testing.T) {
	tx := startMatrix(t, "matrix")
	if err := tx.Close(); err != nil {
		t.Fatalf("Close = %v", err)
	}
	if err := tx.Close(); err != nil {
		t.Fatalf("second Close = %v", err)
	}
	if err := tx.Authenticate(testPassword); err == nil {
		t.Fatal("Authenticate after Close succeeded")
	}
}

// TestWrapperConcurrent runs many transactions in parallel to exercise the
// shared conversation callback and the appdata registry.
func TestWrapperConcurrent(t *testing.T) {
	if wrapperSkipReason != "" {
		t.Skip(wrapperSkipReason)
	}
	var wg sync.WaitGroup
	errs := make(chan error, 32)
	for i := range 32 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			tx, err := Start(testUser, &Options{Service: "matrix"})
			if err != nil {
				errs <- err
				return
			}
			defer tx.Close()
			password, wantErr := testPassword, error(nil)
			if i%2 == 1 {
				password, wantErr = "wrong", ErrAuth
			}
			if err := tx.Authenticate(password); !errors.Is(err, wantErr) && err != wantErr {
				errs <- fmt.Errorf("goroutine %d: Authenticate = %v, want %v", i, err, wantErr)
			}
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		t.Error(err)
	}
}
