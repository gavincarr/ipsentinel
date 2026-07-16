# Design: per-host config file with check types (`-c/--config`)

Date: 2026-07-16
Status: approved

## Problem

On AWS EC2 instances the public IP is a 1:1 NAT mapping held in AWS
infrastructure, not configured on the instance itself, so it never appears in
`ip address` output. ipsentinel checks for such hosts always fail. The public
IP *is* queryable from the instance via the Instance Metadata Service (IMDS)
at `169.254.169.254`.

ipsentinel needs a way to know, per host, which kind of check to run.

## Requirements

- New `-c/--config PATH` flag naming a YAML config file.
- `--concurrency` moves its short flag from `-c` to `-C`.
- Config is a map of maps keyed by **unstripped** hostname (the hostname as it
  appears on stdin, before `-s`/`-S` stripping).
- The only supported second-level key for now is `type`, with values
  `iproute2` (default) or `aws`.
- Hosts absent from the config, or present with an empty `type`, default to
  `iproute2`. No `-c` flag means all hosts are `iproute2`.
- An `aws` check must match the expected IP against `ip address` output *plus*
  the IMDS public IPv4, so it works whether the input IP is the private
  (on-interface) or public (NAT'd) address.

## Design

### CLI changes

```go
Config      string `kong:"short='c',placeholder='PATH'"` // help: path to YAML config file mapping hostnames to per-host settings
Concurrency int    `kong:"short='C',default='8'"`        // was short='c'; help text unchanged
```

### Config file format

YAML (new dependency: `gopkg.in/yaml.v3`):

```yaml
web1.example.com:
  type: aws
web2.example.com:
  type: iproute2
```

Parsed into `map[string]HostConfig` with:

```go
type HostConfig struct {
    Type string `yaml:"type"`
}
```

Decoding uses `yaml.Decoder` with `KnownFields(true)` so unknown second-level
keys (e.g. a `tyep:` typo) fail loudly rather than being silently ignored.

`loadConfig(path string) (map[string]HostConfig, error)` reads and validates
the file. Validation checks every non-empty `type` value against the keys of
the `checkCommands` map (single source of truth for known types).

### Startup behaviour

`main` calls `loadConfig` when `-c` is given, before `run`. Any error —
missing/unreadable file, malformed YAML, unknown key, unknown type — is
reported via `slog.Error` followed by `os.Exit(1)` (never stdlib `log`), and
no checks run. Without `-c` the config map is nil.

Config entries for hostnames that never appear on stdin are silently ignored
(the config may cover a superset of the current input).

### Dispatch

```go
var checkCommands = map[string]string{
    "iproute2": "ip address",
    "aws":      awsCommand, // see below
}
```

- `Check` gains a `Type string` field.
- `parseInput` gains a `config map[string]HostConfig` parameter. The lookup
  happens after hostname validation but **before** `-s`/`-S` stripping, since
  the config is keyed by the unstripped hostname. Missing entry or empty
  `Type` resolves to `iproute2`.
- `runCheck` passes `checkCommands[c.Type]` as the single remote-command
  argument to ssh (the remote shell word-splits it; for `iproute2` this is
  behaviourally identical to the current `"ip", "address"` args).

### The aws remote command

POSIX shell snippet, one ssh round-trip:

```sh
ip address
TOKEN=$(curl -sf -m 2 -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" http://169.254.169.254/latest/api/token 2>/dev/null) || true
curl -sf -m 2 ${TOKEN:+-H "X-aws-ec2-metadata-token: $TOKEN"} http://169.254.169.254/latest/meta-data/public-ipv4 || true
```

- IMDSv2 first; if no token is obtained the header is omitted, giving a
  graceful IMDSv1 fallback.
- `|| true` on the curls: an IMDS hiccup or missing curl binary degrades to
  plain `ip address` matching. If the expected IP is the public one the check
  still fails and alerts ("ip not found"); it just cannot distinguish why.
- `-m 2` caps each curl call well inside the overall ssh timeout.
- The existing `ipPresent` token-matching works unchanged on the combined
  output (the IMDS response is a bare IP, which tokenises cleanly).

### Error handling summary

| Failure | Behaviour |
|---|---|
| `-c` file missing / unreadable / bad YAML / unknown key / unknown type | startup error via `slog.Error`, exit 1, no checks run |
| Config host not present in stdin input | silently ignored |
| aws host: IMDS unreachable or curl missing | degrades to `ip address` output only; check fails iff IP absent there too |

## Testing

- `loadConfig`: valid file, missing file, malformed YAML, unknown type,
  unknown second-level key, empty type defaulting to `iproute2`.
- `parseInput`: config lookup uses the unstripped hostname even when `-s` or
  `-S` is active; nil config defaults everything to `iproute2`.
- Command construction: table test that each `Check.Type` selects the right
  `checkCommands` entry and ssh argv is assembled correctly.
- Existing `parseInput` tests updated for the signature change.

## Documentation

README gains a "Configuration file" section documenting `-c`, the YAML shape,
and the `aws` type — including the why: EC2 public IPs live in AWS
infrastructure (1:1 NAT), not on the instance, so they are invisible to
`ip address` and must come from IMDS.

## Alternatives considered

- **Checker interface** (one implementation per type, mirroring `Alerter`):
  rejected as YAGNI — both types verify identically via `ipPresent` on
  combined output; the interface would wrap a constant string.
- **Client-side AWS API** (`DescribeInstances` from ipsentinel itself):
  rejected — authoritative but drags in the AWS SDK, credentials, and region
  config; a different tool.
- **TOML/JSON config**: YAML chosen for minimal per-entry boilerplate and
  comment support.
