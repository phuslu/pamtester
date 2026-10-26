# pamtester

Verify and change users' login passwords through the OS authentication stack — no cgo required.

| Platform | Backend |
| --- | --- |
| Linux | Linux-PAM (`libpam.so.0`) via [purego](https://github.com/ebitengine/purego) |
| macOS | OpenPAM (`libpam.2.dylib`) via purego |
| Windows | `LogonUserW` / `NetUserChangePassword` |
| others | stub, `Start` returns `errors.ErrUnsupported` |

Build with `-tags nopamtester` to compile the stub on every platform (e.g. to
drop the purego dependency from a binary that never authenticates).

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
    // "" means the current user. Non-root processes can only verify their
    // own password; checking other accounts requires root.
    t, err := pamtester.Start("", nil)
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

    // Check the account itself (expired, locked, access rules)
    if err := t.AcctMgmt(); errors.Is(err, pamtester.ErrNewAuthTokReqd) {
        fmt.Println("password expired, must be changed")
    }

    // Change password (equivalent to passwd; writing /etc/shadow
    // generally requires root on Debian/Ubuntu)
    if err := t.ChangeAuthTok("secret", "n3w-Secret!"); err != nil {
        // Module messages such as "BAD PASSWORD: ..." are included in err
        // and also available via t.Messages().
        fmt.Fprintln(os.Stderr, "change failed:", err)
    }
}
```

## Errors

Every failure wraps a `pamtester.Error` using Linux-PAM numbering on all
platforms (OpenPAM and Win32 codes are translated), so use `errors.Is`:

| Error | Meaning |
| --- | --- |
| `ErrAuth` | wrong password |
| `ErrUserUnknown` | no such user |
| `ErrNewAuthTokReqd` | password correct but expired; must be changed |
| `ErrAcctExpired` | account expired or disabled |
| `ErrMaxTries` | account locked out |
| `ErrPermDenied` | access denied (e.g. pam_access, logon restrictions) |
| `ErrAuthTok`, `ErrAuthTokRecovery` | password change rejected / wrong old password |

## Privileges

- **Verify own password:** no root needed (Linux delegates to the setuid
  `unix_chkpwd` helper).
- **Verify other users:** root on Linux.
- **Change password:** root on Debian/Ubuntu (writes `/etc/shadow`); RHEL's
  setuid `unix_update` and macOS OpenDirectory allow users to change their own.

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
