// Command pamtester is a small CLI demo that reads a password from stdin
// and verifies it against the current user's PAM account.
//
// Note: for simplicity, the password is read as plaintext (echoed in the
// terminal). Production code should use golang.org/x/term.ReadPassword
// to suppress input echo.
package main

import (
	"bufio"
	"fmt"
	"os"
	"os/user"
	"strings"

	"github.com/phuslu/pamtester"
)

func main() {
	u, err := user.Current()
	if err != nil {
		fmt.Fprintln(os.Stderr, "failed to get current user:", err)
		os.Exit(1)
	}

	fmt.Print("Enter password to verify: ")
	reader := bufio.NewReader(os.Stdin)
	line, _ := reader.ReadString('\n')
	password := strings.TrimRight(line, "\r\n")

	t, err := pamtester.Start(u.Username, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "pam start failed:", err)
		os.Exit(1)
	}
	defer t.Close()

	if err := t.Authenticate(password); err != nil {
		fmt.Fprintln(os.Stderr, "verification failed:", err)
		os.Exit(1)
	}
	fmt.Println("password correct")
}
