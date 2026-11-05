// The authorized-keys command: instead of running checks, generate OpenSSH
// authorized_keys lines that force the monitoring key to run exactly the
// command ipsentinel would send each host (or each check variant). The
// forced command depends only on a host's check; connect changes only the
// ssh options on the monitoring side.
package main

import (
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"maps"
	"os"
	"slices"
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
		return "", fmt.Errorf("remote command for check %s contains a backslash, which cannot be safely quoted for authorized_keys: %q",
			c.CheckName, flat)
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

// akRow is one row of authorized-keys output: a label (a host as given, or
// a check variant name) and its authorized_keys line.
type akRow struct {
	label, line string
}

// writeTable writes rows to w as a two-column table: the label, padded with
// spaces to the longest label plus two, then the authorized_keys line, so
// every line starts in the same column. No tabs, no header, no trailing
// whitespace. Labels never contain whitespace (hosts are validHostname, and
// variant names are fixed), so `while read -r label line` with the default
// IFS splits each row back into the label and the byte-identical line: read
// strips the padding before the last field but keeps its internal spacing.
func writeTable(w io.Writer, rows []akRow) error {
	width := 0
	for _, r := range rows {
		width = max(width, len(r.label))
	}
	width += 2
	for _, r := range rows {
		if _, err := fmt.Fprintf(w, "%-*s%s\n", width, r.label, r.line); err != nil {
			return err
		}
	}
	return nil
}

// variantCheckOrder is the preferred display order of checks in variant
// mode. Checks in checkCommands but missing here still appear, sorted, after
// these, so a new check can never be silently left out.
var variantCheckOrder = []string{"iproute2", "aws", "ifconfig", checkNone}

// checkVariants returns every check in checkCommands, in display order (see
// variantCheckOrder). Each check is one variant: its name is the row label,
// and its forced command that of Check{CheckName: name}.
func checkVariants() []string {
	var names []string
	for _, n := range variantCheckOrder {
		if _, ok := checkCommands[n]; ok {
			names = append(names, n)
		}
	}
	for _, n := range slices.Sorted(maps.Keys(checkCommands)) {
		if !slices.Contains(names, n) {
			names = append(names, n)
		}
	}
	return names
}

// resolveHost builds the Check for host (labelled exactly as given; no
// stripping) from config. An exact config key wins. Otherwise the keys
// starting with host+"." are candidates, so a short name like web1 finds
// web1.example.com: none means host isn't configured (defaults); one is
// used; several are fine only if they all yield the same forced command
// (their connect modes may differ, as connect doesn't affect it), else it's
// an error naming each candidate and its check.
func resolveHost(host string, config Config) (Check, error) {
	mk := func(hc HostConfig) Check { return config.check(host, hc) }
	if hc, ok := config.Hosts[host]; ok {
		return mk(hc), nil
	}
	var keys []string
	for k := range config.Hosts {
		if strings.HasPrefix(k, host+".") {
			keys = append(keys, k)
		}
	}
	slices.Sort(keys)
	if len(keys) == 0 {
		return mk(HostConfig{}), nil
	}
	c := mk(config.Hosts[keys[0]])
	want := remoteCommand(c)
	for _, k := range keys[1:] {
		if remoteCommand(mk(config.Hosts[k])) != want {
			descs := make([]string, len(keys))
			for i, k := range keys {
				descs[i] = k + " (" + mk(config.Hosts[k]).CheckName + ")"
			}
			return Check{}, fmt.Errorf("ambiguous: matches config entries with different checks: %s",
				strings.Join(descs, ", "))
		}
	}
	return c, nil
}

// runAuthorizedKeys implements the authorized-keys command, writing a table
// of authorized_keys lines to w (see writeTable). It deliberately takes its
// hosts as a list, never a reader: it must not read stdin. With hosts, it
// writes one row per distinct host (first-seen order), labelled as given and
// resolved against config by resolveHost; an invalid or unresolvable host is
// logged and skipped. Without hosts, it writes one row per check variant
// (see checkVariants), ignoring config. A missing --from (or IPSENTINEL_FROM) is warned about,
// since the lines then accept the key from anywhere. Returns the exit code:
// 1 if any host was skipped, else 0.
func runAuthorizedKeys(hosts []string, config Config, log *slog.Logger,
	w io.Writer, pubkey string, from []string) int {
	if len(from) == 0 {
		log.Warn("no --from or IPSENTINEL_FROM given; generated lines allow the key from any address")
	}

	var rows []akRow
	var skipped int
	add := func(label string, c Check) {
		forced, err := forcedCommand(c)
		if err != nil {
			log.Error("cannot build forced command; skipping", "host", label, "err", err)
			skipped++
			return
		}
		rows = append(rows, akRow{label, authorizedKeysLine(forced, from, pubkey)})
	}

	if len(hosts) == 0 {
		for _, n := range checkVariants() {
			add(n, Check{CheckName: n})
		}
	} else {
		seen := make(map[string]bool)
		for _, host := range hosts {
			if seen[host] {
				continue
			}
			seen[host] = true
			if !validHostname.MatchString(host) {
				log.Error("invalid hostname; skipping", "host", host)
				skipped++
				continue
			}
			c, err := resolveHost(host, config)
			if err != nil {
				log.Error("cannot resolve check; skipping", "host", host, "err", err)
				skipped++
				continue
			}
			add(host, c)
		}
	}

	if err := writeTable(w, rows); err != nil {
		log.Error("writing output", "err", err)
		return 1
	}
	if skipped > 0 {
		log.Warn("finished with failures", "lines", len(rows), "skipped", skipped)
		return 1
	}
	log.Info("generated authorized_keys lines", "lines", len(rows))
	return 0
}
