//go:build linux

// Command login authenticates a user through the Linux "login" PAM service
// and starts their login shell.
//
// A non-root caller may only authenticate and log in as the account with the
// caller's real UID. Root may select any local account.
package main

import (
	"bufio"
	"errors"
	"fmt"
	"io"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"

	"github.com/phuslu/pamtester"
	"golang.org/x/term"
)

const defaultPath = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"

type commandOptions struct {
	preserveEnv bool
	rhost       string
	loginName   string
	username    string
}

var errHelp = errors.New("help requested")

func main() {
	opts, err := parseFlags(os.Args[1:])
	if err != nil {
		if errors.Is(err, errHelp) {
			return
		}
		fmt.Fprintln(os.Stderr, "login:", err)
		os.Exit(2)
	}
	if err := run(opts); err != nil {
		fmt.Fprintln(os.Stderr, "login:", err)
		os.Exit(1)
	}
}

func parseFlags(args []string) (commandOptions, error) {
	var opts commandOptions
	parseOptions := true
	usernameSet := false
	for i := 0; i < len(args); i++ {
		arg := args[i]
		if parseOptions && arg == "--" {
			parseOptions = false
			continue
		}
		if !parseOptions || arg == "" || arg[0] != '-' || arg == "-" {
			if usernameSet {
				printUsage()
				return commandOptions{}, errors.New("too many arguments")
			}
			opts.username = arg
			usernameSet = true
			continue
		}

		name, value, hasValue := splitOption(arg)
		switch name {
		case "p":
			if hasValue {
				preserveEnv, err := strconv.ParseBool(value)
				if err != nil {
					return commandOptions{}, fmt.Errorf("invalid value %q for -p: %w", value, err)
				}
				opts.preserveEnv = preserveEnv
			} else {
				opts.preserveEnv = true
			}
		case "h", "login-name":
			if !hasValue {
				if i+1 >= len(args) {
					return commandOptions{}, fmt.Errorf("option %s requires a value", arg)
				}
				i++
				value = args[i]
			}
			if name == "h" {
				opts.rhost = value
			} else {
				opts.loginName = value
			}
		case "help":
			printUsage()
			return commandOptions{}, errHelp
		default:
			printUsage()
			return commandOptions{}, fmt.Errorf("unknown option %s", arg)
		}
	}
	return opts, nil
}

func splitOption(arg string) (name, value string, hasValue bool) {
	name = strings.TrimPrefix(arg, "-")
	name = strings.TrimPrefix(name, "-")
	if before, after, ok := strings.Cut(name, "="); ok {
		return before, after, true
	}
	return name, "", false
}

func printUsage() {
	fmt.Fprintln(os.Stderr, "usage: login [-p] [-h host] [-login-name name] [username]")
	fmt.Fprintln(os.Stderr, "  -h host")
	fmt.Fprintln(os.Stderr, "    \tremote host for PAM_RHOST")
	fmt.Fprintln(os.Stderr, "  -login-name name")
	fmt.Fprintln(os.Stderr, "    \tnon-root login name (defaults to LOGIN_NAME)")
	fmt.Fprintln(os.Stderr, "  -p")
	fmt.Fprintln(os.Stderr, "    \tdo not clear the environment")
}

func run(opts commandOptions) error {
	realUID := os.Getuid()
	current, err := user.LookupId(strconv.Itoa(realUID))
	if err != nil {
		return fmt.Errorf("look up current user: %w", err)
	}
	loginName := ""
	if realUID != 0 {
		// The login name lets the invoking login program display a name
		// that differs from the current NSS account. It never changes the
		// account used for PAM or for dropping privileges.
		loginName = resolveLoginName(opts)
	}

	reader := bufio.NewReader(os.Stdin)
	username := opts.username
	for {
		targetName := username
		username = "" // A supplied username applies to the first attempt only.
		if targetName == "" {
			fmt.Fprint(os.Stderr, "login: ")
			targetName, err = readLine(reader)
			if errors.Is(err, io.EOF) {
				return nil
			}
			if err != nil {
				return fmt.Errorf("read username: %w", err)
			}
			if targetName == "" {
				targetName = current.Username
			}
		}

		var target *user.User
		loginNameMatches := true
		if realUID != 0 {
			expectedName := current.Username
			if loginName != "" {
				expectedName = loginName
			}
			// Delay rejecting a mismatched name until after authentication so
			// callers cannot use the response timing to enumerate login names.
			loginNameMatches = targetName == expectedName
			target = current
		} else {
			target, err = user.Lookup(targetName)
			if err != nil {
				printLoginIncorrect()
				continue
			}
		}

		password, err := readPassword(reader)
		if err != nil {
			return fmt.Errorf("read password: %w", err)
		}

		pamUser, err := authenticate(target.Username, current.Username, opts.rhost, password)
		clear(password)
		if err != nil {
			if isLoginRejected(err) {
				printLoginIncorrect()
				continue
			}
			return err
		}

		pamTarget, err := user.Lookup(pamUser)
		if err != nil {
			return fmt.Errorf("look up PAM user %q: %w", pamUser, err)
		}
		if realUID != 0 {
			if pamTarget.Uid != current.Uid || !loginNameMatches {
				printLoginIncorrect()
				continue
			}
			// LOGIN_NAME is display-only. Use the real current account for
			// supplementary groups, credentials and the login shell.
			target = current
		} else {
			target = pamTarget
		}

		return startLoginShell(target, opts.preserveEnv)
	}
}

func resolveLoginName(opts commandOptions) string {
	if opts.loginName != "" {
		return opts.loginName
	}
	return os.Getenv("LOGIN_NAME")
}

func isLoginRejected(err error) bool {
	return errors.Is(err, pamtester.ErrAuth) ||
		errors.Is(err, pamtester.ErrUserUnknown) ||
		errors.Is(err, pamtester.ErrMaxTries) ||
		errors.Is(err, pamtester.ErrAcctExpired) ||
		errors.Is(err, pamtester.ErrPermDenied) ||
		errors.Is(err, pamtester.ErrNewAuthTokReqd)
}

func printLoginIncorrect() {
	fmt.Fprintln(os.Stderr, "Login incorrect")
}

func authenticate(username, requestingUser, rhost string, password []byte) (string, error) {
	tx, err := pamtester.Start(username, &pamtester.Options{
		Service: "login",
		RHost:   rhost,
		TTY:     terminalName(),
		RUser:   requestingUser,
	})
	if err != nil {
		return "", fmt.Errorf("start PAM transaction: %w", err)
	}

	pamUser := username
	defer func() {
		_ = tx.Close()
	}()

	if err := tx.Authenticate(string(password)); err != nil {
		return "", err
	}
	printMessages(tx.Messages())

	if err := tx.AcctMgmt(); err != nil {
		return "", err
	}
	printMessages(tx.Messages())

	pamUser, err = tx.User()
	if err != nil {
		return "", fmt.Errorf("read PAM user: %w", err)
	}
	if pamUser == "" {
		return "", errors.New("PAM returned an empty user")
	}

	if err := tx.Close(); err != nil {
		return "", fmt.Errorf("close PAM transaction: %w", err)
	}
	return pamUser, nil
}

func printMessages(messages []string) {
	for _, message := range messages {
		fmt.Fprintln(os.Stderr, message)
	}
}

func readLine(reader *bufio.Reader) (string, error) {
	line, err := reader.ReadString('\n')
	if err != nil && len(line) == 0 {
		return "", err
	}
	return strings.TrimRight(line, "\r\n"), nil
}

func readPassword(reader *bufio.Reader) ([]byte, error) {
	fd := int(os.Stdin.Fd())
	if !term.IsTerminal(fd) {
		fmt.Fprint(os.Stderr, "Password: ")
		line, err := readLine(reader)
		fmt.Fprintln(os.Stderr)
		return []byte(line), err
	}

	fmt.Fprint(os.Stderr, "Password: ")
	password, err := term.ReadPassword(fd)
	fmt.Fprintln(os.Stderr)
	if err != nil {
		return nil, err
	}
	return password, nil
}

func terminalName() string {
	for _, fd := range []uintptr{os.Stdin.Fd(), os.Stderr.Fd()} {
		path, err := os.Readlink(fmt.Sprintf("/proc/self/fd/%d", fd))
		if err == nil && strings.HasPrefix(path, "/dev/") {
			return strings.TrimPrefix(path, "/dev/")
		}
	}
	return ""
}

func startLoginShell(target *user.User, preserveEnv bool) error {
	uid, gid, err := userIDs(target)
	if err != nil {
		return err
	}
	if os.Getuid() != 0 && os.Getuid() != uid {
		return errors.New("refusing to switch to another user")
	}

	shell := loginShell(target.Username)
	if shell == "" {
		return fmt.Errorf("no login shell configured for %s", target.Username)
	}

	if os.Geteuid() == 0 {
		groups, err := userGroups(target, gid)
		if err != nil {
			return err
		}
		if err := syscall.Setgroups(groups); err != nil {
			return fmt.Errorf("set supplementary groups: %w", err)
		}
		if err := syscall.Setgid(gid); err != nil {
			return fmt.Errorf("set gid: %w", err)
		}
		if err := syscall.Setuid(uid); err != nil {
			return fmt.Errorf("set uid: %w", err)
		}
	}
	if os.Getuid() != uid || os.Geteuid() != uid {
		return fmt.Errorf("credential switch failed: uid=%d euid=%d, want %d", os.Getuid(), os.Geteuid(), uid)
	}

	if err := os.Chdir(target.HomeDir); err != nil {
		return fmt.Errorf("change directory to %s: %w", target.HomeDir, err)
	}
	syscall.Umask(0o022)

	env := loginEnvironment(target, shell, preserveEnv)
	argv0 := "-" + filepath.Base(shell)
	if err := syscall.Exec(shell, []string{argv0}, env); err != nil {
		return fmt.Errorf("exec %s: %w", shell, err)
	}
	return nil
}

func userIDs(target *user.User) (uid, gid int, err error) {
	uid, err = strconv.Atoi(target.Uid)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid uid %q: %w", target.Uid, err)
	}
	gid, err = strconv.Atoi(target.Gid)
	if err != nil {
		return 0, 0, fmt.Errorf("invalid gid %q: %w", target.Gid, err)
	}
	return uid, gid, nil
}

func userGroups(target *user.User, primaryGID int) ([]int, error) {
	ids, err := target.GroupIds()
	if err != nil {
		return nil, fmt.Errorf("look up groups for %s: %w", target.Username, err)
	}

	groups := make([]int, 0, len(ids)+1)
	seen := make(map[int]bool, len(ids)+1)
	add := func(id int) {
		if !seen[id] {
			seen[id] = true
			groups = append(groups, id)
		}
	}
	add(primaryGID)
	for _, idText := range ids {
		id, err := strconv.Atoi(idText)
		if err != nil {
			return nil, fmt.Errorf("invalid supplementary gid %q: %w", idText, err)
		}
		add(id)
	}
	return groups, nil
}

func loginShell(username string) string {
	file, err := os.Open("/etc/passwd")
	if err != nil {
		return "/bin/sh"
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		fields := strings.Split(scanner.Text(), ":")
		if len(fields) >= 7 && fields[0] == username && isExecutablePath(fields[6]) {
			return fields[6]
		}
	}

	// NSS users need not have a local passwd entry. /bin/sh is a safe
	// fallback; it will still source the account's profile through argv[0].
	return "/bin/sh"
}

func isExecutablePath(path string) bool {
	return filepath.IsAbs(path) && !strings.ContainsRune(path, 0)
}

func loginEnvironment(target *user.User, shell string, preserve bool) []string {
	var env []string
	if preserve {
		env = append(env, os.Environ()...)
	} else if termName := os.Getenv("TERM"); termName != "" {
		env = append(env, "TERM="+termName)
	}

	values := map[string]string{
		"HOME":    target.HomeDir,
		"LOGNAME": target.Username,
		"MAIL":    filepath.Join("/var/mail", target.Username),
		"PATH":    defaultPath,
		"SHELL":   shell,
		"USER":    target.Username,
	}
	for key, value := range values {
		env = setEnv(env, key, value)
	}
	return env
}

func setEnv(env []string, key, value string) []string {
	prefix := key + "="
	filtered := env[:0]
	for _, entry := range env {
		if !strings.HasPrefix(entry, prefix) {
			filtered = append(filtered, entry)
		}
	}
	return append(filtered, prefix+value)
}
