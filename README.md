# pamtester

Verify a user's login password via Linux PAM using [purego](https://github.com/ebitengine/purego) — no cgo required.

## Example

```go
package main

import (
    "fmt"
    "os"

    "github.com/phuslu/pamtester"
)

func main() {
    err := pamtester.CheckUserPassword("root", "secret")
    if err != nil {
        fmt.Fprintln(os.Stderr, "auth failed:", err)
        os.Exit(1)
    }
    fmt.Println("password correct")
}
```

## CLI

```bash
go run ./cmd/pamtester/
```
