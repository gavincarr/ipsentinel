// The authorized-keys command: instead of running checks, generate one
// OpenSSH authorized_keys line per ssh target that forces the monitoring key
// to run exactly the command ipsentinel would send that host.
package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"os"
	"strings"
	"unicode"
)

// forcedCommand returns c's remote command (see remoteCommand) as a value
// ready to drop between the double quotes of an authorized_keys
// command="..." option. The command is flattened to one line by joining its
// lines with "; " — every line of the shipped commands is a complete shell
// command, so this is equivalent — and each `"` is escaped as `\"`, the only
// escape sshd's option dequoting understands. A backslash anywhere in the
// command is a programming error: sshd copies `\x` through literally but
// rewrites `\"`, so a command mixing backslashes with escaped quotes is easy
// to get subtly wrong. It's reported as an error rather than risk emitting a
// line that forces a different command than ipsentinel sends.
func forcedCommand(c Check) (string, error) {
	flat := strings.Join(strings.Split(remoteCommand(c), "\n"), "; ")
	if strings.Contains(flat, `\`) {
		return "", fmt.Errorf("remote command for type %s contains a backslash, which cannot be safely quoted for authorized_keys: %q",
			describeType(c), flat)
	}
	return strings.ReplaceAll(flat, `"`, `\"`), nil
}

// authorizedKeysLine assembles an authorized_keys line: an optional
// from="..." option, then restrict (which disables forwarding, pty, X11,
// ~/.ssh/rc etc.; OpenSSH >= 7.2), the forced command, and the public key
// line as given. forced must already be escaped (see forcedCommand) and from
// already validated (see parseFrom).
func authorizedKeysLine(forced string, from []string, pubkey string) string {
	var b strings.Builder
	if len(from) > 0 {
		b.WriteString(`from="` + strings.Join(from, ",") + `",`)
	}
	b.WriteString(`restrict,command="` + forced + `" ` + pubkey)
	return b.String()
}

// parseFrom splits a comma-separated --from value into sshd from= patterns.
// Items are trimmed; empty items, and items containing a double quote,
// whitespace or a backslash (any of which would break or subvert the quoted
// option), are rejected.
func parseFrom(s string) ([]string, error) {
	var patterns []string
	for item := range strings.SplitSeq(s, ",") {
		item = strings.TrimSpace(item)
		switch {
		case item == "":
			return nil, fmt.Errorf("--from %q: empty pattern", s)
		case strings.ContainsAny(item, `"\`), strings.ContainsFunc(item, unicode.IsSpace):
			return nil, fmt.Errorf("--from %q: pattern %q must not contain quotes, backslashes or whitespace", s, item)
		}
		patterns = append(patterns, item)
	}
	return patterns, nil
}

// pubkeyTypePrefixes are the key-type prefixes accepted in a public key line:
// ssh-ed25519, ssh-rsa, ecdsa-sha2-nistp256, sk-ssh-ed25519@openssh.com, etc.
var pubkeyTypePrefixes = []string{"ssh-", "ecdsa-sha2-", "sk-"}

// loadPubkey reads and validates the OpenSSH public key file at path (see
// parsePubkey).
func loadPubkey(path string) (string, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	line, err := parsePubkey(string(data))
	if err != nil {
		return "", fmt.Errorf("%s: %w", path, err)
	}
	return line, nil
}

// parsePubkey validates an OpenSSH public key file's contents and returns its
// single line, trimmed but otherwise as-is (type, base64 key, optional
// comment). This is a shape check, not a cryptographic parse: it guards
// against the easy mistakes — the private key instead of the .pub, an
// authorized_keys file, an empty or multi-key file.
func parsePubkey(data string) (string, error) {
	line := strings.TrimSpace(data)
	switch {
	case line == "":
		return "", errors.New("public key file is empty")
	case strings.Contains(line, "-----BEGIN"):
		return "", errors.New("looks like a private key; pass the .pub file")
	case strings.ContainsAny(line, "\r\n"):
		return "", errors.New("public key file must contain exactly one line")
	}
	fields := strings.Fields(line)
	if len(fields) < 2 {
		return "", errors.New("public key line must have at least a key type and a base64 key")
	}
	if !hasAnyPrefix(fields[0], pubkeyTypePrefixes) {
		return "", fmt.Errorf("unrecognised key type %q (want ssh-*, ecdsa-sha2-* or sk-*)", fields[0])
	}
	if _, err := base64.StdEncoding.DecodeString(fields[1]); err != nil {
		return "", fmt.Errorf("key is not valid base64: %w", err)
	}
	return line, nil
}

func hasAnyPrefix(s string, prefixes []string) bool {
	for _, p := range prefixes {
		if strings.HasPrefix(s, p) {
			return true
		}
	}
	return false
}

// describeType renders c's check type for log messages, including any
// ip_version, since that changes the command too.
func describeType(c Check) string {
	if c.IPVersion != "" {
		return c.Type + " (ip_version " + c.IPVersion + ")"
	}
	return c.Type
}

// runAuthorizedKeys implements the authorized-keys command. It parses checks
// from r exactly as a check run does (same config, stripping and
// parse-failure alerts), then writes one TSV line `<target>\t<authorized_keys line>` to w
// per distinct ssh target, in first-seen order. tinydns-style input often
// lists a host twice (A and AAAA), so targets are deduped. A target reached
// with differing forced commands (two input names stripped to one target but
// configured with different types) is an error: it's logged and omitted
// rather than guessed at. Returns the exit code: 1 if there were parse
// failures or omitted targets, else 0.
func runAuthorizedKeys(cli CLI, config map[string]HostConfig, log *slog.Logger,
	r io.Reader, w io.Writer, pubkey string, from []string) int {
	alerter := LogAlerter{log: log}

	checks, parseFailures := parseInput(r, alerter, cli.StripAll, cli.Strip, config)
	if parseFailures > 0 {
		log.Warn("input had malformed lines", "count", parseFailures)
	}
	log.Info("parsed input", "checks", len(checks))

	type target struct {
		first  Check
		forced string
		bad    bool // conflict or unbuildable command: omit from output
	}
	var order []string
	targets := make(map[string]*target)
	for _, c := range checks {
		forced, err := forcedCommand(c)
		t, seen := targets[c.Hostname]
		if !seen {
			t = &target{first: c, forced: forced}
			targets[c.Hostname] = t
			order = append(order, c.Hostname)
		}
		switch {
		case err != nil:
			log.Error("cannot build forced command", "target", c.Hostname, "err", err)
			t.bad = true
		case seen && !t.bad && forced != t.forced:
			log.Error("conflicting check types for one ssh target; omitting it",
				"target", c.Hostname, "type", describeType(t.first), "other_type", describeType(c))
			t.bad = true
		}
	}

	var omitted, written int
	for _, name := range order {
		t := targets[name]
		if t.bad {
			omitted++
			continue
		}
		if _, err := fmt.Fprintf(w, "%s\t%s\n", name, authorizedKeysLine(t.forced, from, pubkey)); err != nil {
			log.Error("writing output", "err", err)
			return 1
		}
		written++
	}

	if parseFailures > 0 || omitted > 0 {
		log.Warn("finished with failures", "targets", written, "omitted", omitted, "parse_failures", parseFailures)
		return 1
	}
	log.Info("generated authorized_keys lines", "targets", written)
	return 0
}
