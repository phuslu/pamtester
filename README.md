# pamtester

Verify and change users' login passwords via Linux PAM using [purego](https://github.com/ebitengine/purego) — no cgo required.

## Example

```go
package main

import (
    "errors"
    "fmt"
    "os"

    "github.com/phuslu/pamtester"
)

func main() {
    t, err := pamtester.Start("root", nil)
    if err != nil {
        fmt.Fprintln(os.Stderr, "pam start failed:", err)
        os.Exit(1)
    }
    defer t.Close()

    // Verify password + account validity (pam_authenticate + pam_acct_mgmt)
    err = t.CheckUserPassword("secret")
    switch {
    case err == nil:
        fmt.Println("password correct")
    case errors.Is(err, pamtester.ErrAuth):
        fmt.Println("wrong password")
    case errors.Is(err, pamtester.ErrNewAuthTokReqd):
        fmt.Println("password correct but expired, must be changed")
    default:
        fmt.Fprintln(os.Stderr, "auth failed:", err)
        os.Exit(1)
    }

    // Change password (equivalent to passwd; writing /etc/shadow
    // generally requires root on Debian/Ubuntu)
    _ = t.ChangeUserPassword("secret", "n3w-Secret!")
}
```

## Transaction API

A `Transaction` corresponds to one `pam_start` .. `pam_end` lifetime and is
bound to one user. Besides the convenience methods above, the PAM primitives
are exposed directly:

```go
t, err := pamtester.Start("alice", &pamtester.Options{
    Service: "login",          // /etc/pam.d/<service>, default "passwd"
    RHost:   "203.0.113.7",    // PAM_RHOST, recorded by faillock/audit logs
    TTY:     "web",            // PAM_TTY
})
if err != nil { ... }
defer t.Close()

err = t.Authenticate("password") // pam_authenticate
err = t.AcctMgmt()               // pam_acct_mgmt: expired/locked/denied?
err = t.ChangeAuthTok("old", "new") // pam_chauthtok
```

All failures wrap a typed `pamtester.Error` (PAM return code), so `errors.Is`
works against sentinels like `ErrAuth`, `ErrUserUnknown`, `ErrAcctExpired`,
`ErrPermDenied`, `ErrNewAuthTokReqd`, `ErrAuthTok`, ...

## CLI

```bash
go run ./cmd/pamtester/
```
