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
	nullUser     = "nopass" // account with an empty password
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
	setItems := filepath.Join(modDir, "pam_set_items.so")
	passdb := filepath.Join(dir, "passdb")

	files := map[string]string{
		"passdb": fmt.Sprintf("%s:%s:matrix\n%s::matrix\n", testUser, testPassword, nullUser),
		"services/matrix": fmt.Sprintf(
			"auth required %[1]s passdb=%[2]s\naccount required %[1]s passdb=%[2]s\npassword required %[1]s passdb=%[2]s\n",
			matrix, passdb),
		"services/verbose": fmt.Sprintf(
			"auth required %[1]s passdb=%[2]s verbose\naccount required %[1]s passdb=%[2]s verbose\npassword required %[1]s passdb=%[2]s verbose\n",
			matrix, passdb),
		"services/chatty": fmt.Sprintf("auth required %s num_lines=2 info error\n", chatty),
		// pam_set_items sets PAM_USER from the environment, standing in for
		// a module that maps the login name to another account.
		"services/rename": fmt.Sprintf("auth required %s\nauth required %s passdb=%s\n", setItems, matrix, passdb),
		"services/echo": fmt.Sprintf(
			"auth required %[1]s passdb=%[2]s echo\npassword required %[1]s passdb=%[2]s echo\n",
			matrix, passdb),
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
		"PAM_USER="+testUser, // read by pam_set_items in the "rename" service
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

func TestWrapperEmptyPassword(t *testing.T) {
	if wrapperSkipReason != "" {
		t.Skip(wrapperSkipReason)
	}
	for _, user := range []string{testUser, nullUser} {
		tx, err := Start(user, &Options{Service: "matrix"})
		if err != nil {
			t.Fatalf("Start(%s): %v", user, err)
		}
		defer tx.Close()
		if err := tx.Authenticate(""); !errors.Is(err, ErrAuth) {
			t.Errorf("Authenticate(%s, \"\") = %v, want ErrAuth", user, err)
		}
	}

	tx, err := Start(nullUser, &Options{Service: "matrix", AllowNullAuthTok: true})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	if err := tx.Authenticate(""); err != nil {
		t.Errorf("Authenticate(%s, \"\") with AllowNullAuthTok = %v", nullUser, err)
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

// recordConv answers prompts with the given replies in order and records
// every message it sees.
type recordConv struct {
	replies []string
	seen    []Style
	texts   []string
}

func (c *recordConv) conv(style Style, msg string) (string, error) {
	c.seen = append(c.seen, style)
	c.texts = append(c.texts, msg)
	if style != PromptEchoOff && style != PromptEchoOn {
		return "", nil
	}
	if len(c.replies) == 0 {
		return "", errors.New("unexpected prompt " + msg)
	}
	r := c.replies[0]
	c.replies = c.replies[1:]
	return r, nil
}

func TestWrapperAuthenticateConv(t *testing.T) {
	tx := startMatrix(t, "matrix")
	c := &recordConv{replies: []string{testPassword}}
	if err := tx.AuthenticateConv(c.conv); err != nil {
		t.Fatalf("AuthenticateConv = %v", err)
	}
	if len(c.seen) != 1 || c.seen[0] != PromptEchoOff {
		t.Errorf("conv saw %v %q, want one PromptEchoOff", c.seen, c.texts)
	}

	tx = startMatrix(t, "echo")
	c = &recordConv{replies: []string{testPassword}}
	if err := tx.AuthenticateConv(c.conv); err != nil {
		t.Fatalf("AuthenticateConv(echo) = %v", err)
	}
	if len(c.seen) != 1 || c.seen[0] != PromptEchoOn {
		t.Errorf("conv saw %v %q, want one PromptEchoOn", c.seen, c.texts)
	}
}

func TestWrapperAuthenticateConvError(t *testing.T) {
	tx := startMatrix(t, "matrix")
	errCancel := errors.New("user cancelled")
	err := tx.AuthenticateConv(func(Style, string) (string, error) { return "", errCancel })
	if !errors.Is(err, errCancel) {
		t.Fatalf("AuthenticateConv = %v, want it to wrap the ConvFunc error", err)
	}
	if err := tx.AuthenticateConv(func(Style, string) (string, error) { return "a\x00b", nil }); !errors.Is(err, errNUL) {
		t.Fatalf("AuthenticateConv(reply with NUL) = %v, want errNUL", err)
	}
	if err := tx.AuthenticateConv(nil); err == nil {
		t.Fatal("AuthenticateConv(nil) succeeded")
	}
}

func TestWrapperAuthenticateConvMessages(t *testing.T) {
	tx := startMatrix(t, "chatty")
	c := &recordConv{}
	if err := tx.AuthenticateConv(c.conv); err != nil {
		t.Fatalf("AuthenticateConv = %v", err)
	}
	var info, errs int
	for _, s := range c.seen {
		switch s {
		case TextInfo:
			info++
		case ErrorMsg:
			errs++
		}
	}
	if info == 0 || errs == 0 {
		t.Errorf("conv saw %v, want both TextInfo and ErrorMsg", c.seen)
	}
	if len(tx.Messages()) != len(c.seen) {
		t.Errorf("Messages() = %d entries, conv saw %d", len(tx.Messages()), len(c.seen))
	}
}

func TestWrapperChangeAuthTokConv(t *testing.T) {
	const newPassword = "c0nv-Secret!"

	tx := startMatrix(t, "matrix")
	err := tx.ChangeAuthTokConv(func(_ Style, prompt string) (string, error) {
		if strings.Contains(strings.ToLower(prompt), "new") {
			return newPassword, nil
		}
		return testPassword, nil
	})
	if err != nil {
		t.Fatalf("ChangeAuthTokConv = %v", err)
	}
	t.Cleanup(func() {
		tx := startMatrix(t, "matrix")
		if err := tx.ChangeAuthTok(newPassword, testPassword); err != nil {
			t.Errorf("restoring password: %v", err)
		}
	})
	if err := startMatrix(t, "matrix").Authenticate(newPassword); err != nil {
		t.Errorf("Authenticate(new) after ChangeAuthTokConv = %v", err)
	}
}

func TestWrapperUser(t *testing.T) {
	tx := startMatrix(t, "matrix")
	if u, err := tx.User(); err != nil || u != testUser {
		t.Fatalf("User() = %q, %v; want %q", u, err, testUser)
	}

	// "Alice" is mapped to alice by pam_set_items before pam_matrix runs.
	if wrapperSkipReason != "" {
		t.Skip(wrapperSkipReason)
	}
	tx, err := Start("Alice", &Options{Service: "rename"})
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Close()
	if u, _ := tx.User(); u != "Alice" {
		t.Errorf("User() before Authenticate = %q, want %q", u, "Alice")
	}
	if err := tx.Authenticate(testPassword); err != nil {
		t.Fatalf("Authenticate = %v", err)
	}
	if u, err := tx.User(); err != nil || u != testUser {
		t.Errorf("User() after Authenticate = %q, %v; want %q", u, err, testUser)
	}

	tx.Close()
	if _, err := tx.User(); err == nil {
		t.Error("User() after Close succeeded")
	}
}
