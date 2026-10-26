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

    // Verify password (pam_authenticate)
    err = t.Authenticate("secret")
    switch {
    case err == nil:
        fmt.Println("password correct")
    case errors.Is(err, pamtester.ErrAuth):
        fmt.Println("wrong password")
    default:
        fmt.Fprintln(os.Stderr, "auth failed:", err)
        os.Exit(1)
    }

    // Change password (equivalent to passwd; writing /etc/shadow
    // generally requires root on Debian/Ubuntu)
    _ = t.ChangeAuthTok("secret", "n3w-Secret!")
}
```

## PAM service

`Start` uses the PAM service named by `Options.Service`, defaulting to
`pamtester.PamService` (`passwd` on Linux, `checkpw` on macOS).

On Linux, `/etc/pam.d/passwd` usually contains only a `password` stack, so
`Authenticate`/`AcctMgmt` rely on Linux-PAM falling back to `/etc/pam.d/other`.
That works on Debian/Ubuntu (where `other` includes `common-auth`), but fails on
systems whose `other` is `pam_deny`. If you mainly verify passwords, pick a
service with an `auth` section explicitly, or ship your own:

```go
t, err := pamtester.Start(user, &pamtester.Options{Service: "login"})
```

```
# /etc/pam.d/myapp
auth    include system-auth   # or: @include common-auth (Debian)
account include system-auth   # or: @include common-account
```

## CLI

```bash
go run ./cmd/pamtester/
```
