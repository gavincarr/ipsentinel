# Design: `-s/--strip` hostname-label stripping

## Summary

Add a `-s/--strip` boolean flag to `ipsentinel`. When set, each hostname read
from stdin is reduced to its **leftmost DNS label** before ssh is invoked
(`foo.example.com` → `foo`). Default behaviour (flag absent) is unchanged.

## Motivation

Operators may feed fully-qualified hostnames on stdin but rely on
`~/.ssh/config` `Host` aliases that use only the short name. `-s` lets the same
input drive ssh without pre-processing the hostname column.

## Semantics

- Keep the **leftmost label only**: everything from the first `.` onward is
  dropped.
  - `foo.example.com` → `foo`
  - `a.b.example.com` → `a`
  - `host` (no dot) → `host` (unchanged)
- Off by default; opt-in per run via `-s`/`--strip`.

## Design

### CLI

Add to the `CLI` struct:

```go
Strip bool `kong:"short='s',help='Strip trailing labels from each hostname, keeping only the leftmost label (foo.example.com => foo).'"`
```

### Where stripping happens

Stripping is applied in `parseInput`, **after** hostname validation:

1. Validate the original hostname exactly as today. An `invalid hostname`
   alert therefore still names precisely what appeared on stdin.
2. If `strip` is set, reduce the validated hostname to its leftmost label
   before constructing the `Check`.

Because the stored `Check.Hostname` becomes the stripped name, everything
downstream — the ssh invocation, failure alerts, and debug logs — uses the
stripped form uniformly. This matches the decision that alerts report the
stripped hostname.

### New helper

```go
// stripHostname returns the leftmost DNS label of host (foo.example.com => foo).
// A host with no dot is returned unchanged.
func stripHostname(host string) string {
    label, _, _ := strings.Cut(host, ".")
    return label
}
```

### Threading the flag

`parseInput` gains a `strip bool` parameter; `run` passes `cli.Strip` through.

## Edge cases

- **No dot**: returned unchanged.
- **Post-strip validity**: the leftmost label's first character equals the
  original hostname's first character, which already passed `validHostname`, so
  the stripped result is still valid. No re-validation is needed.
- **IP-literal host** (`10.0.0.1` → `10`): accepted. `-s` is opt-in and off by
  default, so this only affects callers who explicitly ask for stripping.

## Testing

- `TestStripHostname`: `foo.example.com`→`foo`, `a.b.example.com`→`a`,
  `host`→`host`.
- Extend `parseInput` coverage:
  - `strip=true`: a dotted input hostname is stored as its leftmost label.
  - `strip=false`: existing behaviour is byte-for-byte unchanged.

## Non-goals

- Configurable label counts or suffix matching (`--strip=N`, domain suffix
  removal). YAGNI; can be added later if a real need appears.
