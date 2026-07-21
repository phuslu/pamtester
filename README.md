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

## CLI

```bash
go run ./cmd/pamtester/
```
