// The known-hosts command: for each connect: ip host, print known_hosts
// lines recording the host key already trusted for the host under its ip
// name. With connect: ip, ssh dials the ip with -o HostName=<ip> and looks
// the server's key up under the ip name ([ip]:port, or ip on port 22), not
// under the hostname — so the first `check` run fails every host until the
// ip name has a key. This command connects to nothing: it copies the keys
// ssh already trusts for the host to the ip name. A known_hosts line carries
// only a public key, so this just records "this ip must prove it holds this
// host's private key"; the next check run's handshake does the verifying.
package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"os"
	"os/exec"
	"slices"
	"strings"
	"time"

	"github.com/alecthomas/kong"
)

// KnownHostsCmd holds the settings for the known-hosts command. Strip and
// StripAll mirror CheckCmd's, so the same `-s example.com` that drives check
// works after the command name.
type KnownHostsCmd struct {
	Strip    string `kong:"name='strip',short='s',xor='strip',placeholder='DOMAIN',help='Strip the given domain suffix from each hostname before the ssh check (a leading dot is added if absent, so example.com strips .example.com from foo.example.com => foo).'"`
	StripAll bool   `kong:"name='strip-all',short='S',xor='strip',help='Strip trailing labels from each hostname, keeping only the leftmost label (foo.example.com => foo).'"`
}

// AfterApply rejects check flags given before the known-hosts command name
// (see rejectCheckFlags).
func (k *KnownHostsCmd) AfterApply(kctx *kong.Context) error {
	return rejectCheckFlags(kctx, "known-hosts")
}

// subprocessTimeout bounds each ssh -G and ssh-keygen -F invocation.
const subprocessTimeout = 10 * time.Second

// knownHostsEnv is the known-hosts command's view of the outside world, so
// tests can substitute a fake ssh config while still using real ssh-keygen.
type knownHostsEnv struct {
	// sshConfig returns `ssh -G` output for hostname; with a non-empty ip it
	// is resolved as `check` would run it (-o HostName=<ip>).
	sshConfig func(ctx context.Context, hostname, ip string) (string, error)
	// keygenFind returns `ssh-keygen -F name -f file` output; "" and a nil
	// error when the name is not in the file.
	keygenFind func(ctx context.Context, name, file string) (string, error)
	// salt returns a fresh 20-byte salt for hashing one known_hosts name.
	salt func() ([]byte, error)
}

// realKnownHostsEnv returns the production environment: the real ssh and
// ssh-keygen binaries, and crypto/rand salts.
func realKnownHostsEnv() knownHostsEnv {
	return knownHostsEnv{sshConfig: sshConfig, keygenFind: keygenFind, salt: randomSalt}
}

// sshConfig runs `ssh -G` for hostname, with the HostName override `check`
// uses for connect: ip when ip is non-empty, so Match blocks see the same
// thing. A non-zero exit is an error carrying the trimmed stderr.
func sshConfig(ctx context.Context, hostname, ip string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, subprocessTimeout)
	defer cancel()
	args := []string{"-G"}
	if ip != "" {
		args = append(args, "-o", "HostName="+ip)
	}
	args = append(args, "--", hostname)
	return runCaptured(ctx, "ssh", args...)
}

// keygenFind runs `ssh-keygen -F name -f file`. Exit 1 means the name is not
// in the file; any other failure is an error.
func keygenFind(ctx context.Context, name, file string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, subprocessTimeout)
	defer cancel()
	out, err := runCaptured(ctx, "ssh-keygen", "-F", name, "-f", file)
	var ee *exitError
	if errors.As(err, &ee) && ee.code == 1 {
		return "", nil
	}
	return out, err
}

// exitError is a non-zero subprocess exit, with its exit code and stderr.
type exitError struct {
	cmd    string
	code   int
	stderr string
}

func (e *exitError) Error() string {
	return fmt.Sprintf("%s exited %d: %s", e.cmd, e.code, e.stderr)
}

// runCaptured runs name with args and returns its stdout. A non-zero exit
// is an *exitError; a timeout is reported as such.
func runCaptured(ctx context.Context, name string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, name, args...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	err := cmd.Run()
	if err == nil {
		return stdout.String(), nil
	}
	if ctx.Err() == context.DeadlineExceeded {
		return "", fmt.Errorf("%s timed out after %s", name, subprocessTimeout)
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return stdout.String(), &exitError{name, ee.ExitCode(), strings.TrimSpace(stderr.String())}
	}
	return "", err
}

// randomSalt returns 20 random bytes, the salt size ssh uses (SHA-1 length).
func randomSalt() ([]byte, error) {
	salt := make([]byte, sha1.Size)
	_, err := rand.Read(salt)
	return salt, err
}

// parseSSHConfig parses `ssh -G` output: one "key value" per line, keys
// lowercase. The first occurrence of a key wins, as it does in ssh.
func parseSSHConfig(out string) map[string]string {
	m := make(map[string]string)
	for line := range strings.SplitSeq(out, "\n") {
		k, v, _ := strings.Cut(strings.TrimSpace(line), " ")
		if k == "" {
			continue
		}
		if _, ok := m[k]; !ok {
			m[k] = strings.TrimSpace(v)
		}
	}
	return m
}

// hostKey is a public key as it appears in known_hosts: type and base64.
type hostKey struct {
	typ, key string
}

// parseKeygenFind parses `ssh-keygen -F` output into the keys it trusts and
// the keys it revokes, each in order and deduplicated. Comment ("# Host ...
// found") and blank lines are skipped, as are @cert-authority lines, which
// are never copied to another name. @revoked lines are returned separately
// so callers can subtract them: ssh refuses a revoked key for the name it
// is revoked under, and copying it to another name would turn that explicit
// revocation into fresh trust. The host field may be plain or hashed; it is
// ignored, as is any trailing comment.
func parseKeygenFind(out string) (keys, revoked []hostKey) {
	seen := make(map[hostKey]bool)
	seenRevoked := make(map[hostKey]bool)
	for line := range strings.SplitSeq(out, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Fields(line)
		marker := ""
		if strings.HasPrefix(f[0], "@") {
			marker, f = f[0], f[1:]
		}
		if len(f) < 3 {
			continue
		}
		k := hostKey{f[1], f[2]}
		switch marker {
		case "":
			if !seen[k] {
				seen[k] = true
				keys = append(keys, k)
			}
		case "@revoked":
			if !seenRevoked[k] {
				seenRevoked[k] = true
				revoked = append(revoked, k)
			}
		}
	}
	return keys, revoked
}

// knownHostsName returns the name ssh files host's key under: the host
// itself on port 22, else [host]:port (IPv6 included).
func knownHostsName(host, port string) string {
	if port == "22" {
		return host
	}
	return "[" + host + "]:" + port
}

// hashKnownHostsName returns name in ssh's hashed known_hosts form,
// |1|base64(salt)|base64(HMAC-SHA1(key=salt, msg=name)).
func hashKnownHostsName(name string, salt []byte) string {
	mac := hmac.New(sha1.New, salt)
	mac.Write([]byte(name))
	return "|1|" + base64.StdEncoding.EncodeToString(salt) + "|" + base64.StdEncoding.EncodeToString(mac.Sum(nil))
}

// findKeys returns the keys trusted for name across files, and the keys
// revoked for it, each deduplicated. Files that do not exist are skipped,
// since ssh-keygen -F fails on them; any other stat failure (e.g. permission
// denied) is returned, so an unreadable file cannot hide a key and is
// reported as a problem.
func findKeys(ctx context.Context, env knownHostsEnv, name string, files []string) (keys, revoked []hostKey, err error) {
	for _, f := range files {
		if _, err := os.Stat(f); errors.Is(err, fs.ErrNotExist) {
			continue
		} else if err != nil {
			return nil, nil, err
		}
		out, err := env.keygenFind(ctx, name, f)
		if err != nil {
			return nil, nil, err
		}
		k, r := parseKeygenFind(out)
		for _, x := range k {
			if !slices.Contains(keys, x) {
				keys = append(keys, x)
			}
		}
		for _, x := range r {
			if !slices.Contains(revoked, x) {
				revoked = append(revoked, x)
			}
		}
	}
	return keys, revoked, nil
}

// userKnownHostsFiles returns the user known_hosts files from an ssh -G
// config; knownHostsFiles adds the global ones. ssh -G prints "none"
// literally when a list is disabled; that is not a path, so it is dropped
// rather than left to fail a stat on a relative file called none.
func userKnownHostsFiles(cfg map[string]string) []string {
	return dropNone(strings.Fields(cfg["userknownhostsfile"]))
}

func knownHostsFiles(cfg map[string]string) []string {
	return append(userKnownHostsFiles(cfg), dropNone(strings.Fields(cfg["globalknownhostsfile"]))...)
}

func dropNone(files []string) []string {
	return slices.DeleteFunc(files, func(f string) bool { return f == "none" })
}

// subtractKeys returns keys without those in remove.
func subtractKeys(keys, remove []hostKey) []hostKey {
	var out []hostKey
	for _, k := range keys {
		if !slices.Contains(remove, k) {
			out = append(out, k)
		}
	}
	return out
}

// runKnownHosts implements the known-hosts command: it reads checks like
// run does and, for each connect: ip host, writes to w known_hosts lines
// copying the host's trusted keys to its ip name (see the file comment).
// Keys already recorded under the ip name are not repeated, so a re-run
// prints nothing new; keys printed earlier in this run count as recorded.
// Keys revoked under the host name or the ip name are never printed. A host
// with ssh -G failing, no known key, every key revoked, or an ip name
// already holding a key that is not one of the host's is a problem: it is logged, nothing is
// printed for it, and the exit code is 1. stdout carries only known_hosts
// lines. Returns the exit code.
func runKnownHosts(r io.Reader, stripAll bool, domain string, config Config, log *slog.Logger,
	w io.Writer, env knownHostsEnv) int {
	ctx := context.Background()
	checks, problems := parseInput(r, LogAlerter{log}, stripAll, domain, config)
	// Keys printed this run, by plain ip name.
	printed := make(map[string][]hostKey)
	var lines, ipHosts int
	// The ip side's first user known_hosts file for each host that printed
	// lines ("" when it has none), to tell where the output belongs.
	printedFiles := make(map[string]bool)

	for _, c := range checks {
		if c.Connect != connectIP {
			log.Debug("not connect: ip; skipping", "hostname", c.Hostname, "ip", c.IP)
			continue
		}
		ipHosts++
		n, file, ok := knownHostsFor(ctx, c, env, log, w, printed)
		lines += n
		if n > 0 {
			printedFiles[file] = true
		}
		if !ok {
			problems++
		}
	}

	if ipHosts == 0 {
		// Exit 0 with no output looks like "everything is recorded", which
		// is wrong when the input was never considered at all.
		log.Warn("no connect: ip hosts in input; nothing to do (do they all set connect: ssh_config?)")
	}
	if problems > 0 {
		log.Warn("finished with problems", "lines", lines, "problems", problems)
	}
	switch {
	case lines == 0 && problems == 0 && ipHosts > 0:
		// Not when ipHosts == 0: the Warn above already said why.
		log.Info("nothing new to print")
	case lines > 0:
		// Warn so it shows at the default level: the output is useless
		// until the user appends it somewhere, and new users won't know
		// where. The file is only named when every printing host agrees.
		if len(printedFiles) == 1 && !printedFiles[""] {
			for f := range printedFiles {
				log.Warn(fmt.Sprintf("printed %d known_hosts lines for %s", lines, f))
			}
		} else {
			log.Warn(fmt.Sprintf("printed %d known_hosts lines; they belong in each host's UserKnownHostsFile", lines))
		}
	}
	if problems > 0 {
		return 1
	}
	return 0
}

// hostKeyStatus is the outcome of planHostKeys for one connect: ip check.
type hostKeyStatus int

const (
	// hostKeyAliased: the ip side sets HostKeyAlias, so ssh already
	// verifies the ip against the alias; nothing to do.
	hostKeyAliased hostKeyStatus = iota
	// hostKeyRecorded: every trusted host key is already recorded under the
	// ip name (or was printed earlier in this run).
	hostKeyRecorded
	// hostKeyAddable: add holds at least one key to record under the ip name.
	hostKeyAddable
	// hostKeyNoHostKey: no key is known under the host's usual name.
	hostKeyNoHostKey
	// hostKeyRevoked: every host key is revoked under the host or ip name.
	hostKeyRevoked
	// hostKeyForeignIPKey: the ip name already holds a key that is not one
	// of the host's.
	hostKeyForeignIPKey
	// hostKeyLookupError: ssh -G or a key lookup failed; see err, errSide
	// and errMsg.
	hostKeyLookupError
)

// hostKeyPlan is planHostKeys's decision for one host. Which fields are set
// depends on status: names and files from the point the plan got that far.
type hostKeyPlan struct {
	status hostKeyStatus
	// hostName and ipName are the plain (unhashed) known_hosts names.
	hostName, ipName string
	// ipUserFile is the ip side's first user known_hosts file, "" if none:
	// where printed lines belong.
	ipUserFile string
	// userFilesDiffer: the ip side's user files differ from the host side's
	// (and the ip side has some).
	userFilesDiffer bool
	// hash: the ip side has HashKnownHosts yes.
	hash bool
	// add holds, for hostKeyAddable, the keys to record, in order.
	add []hostKey
	// For hostKeyLookupError: the cause, which lookup failed ("ip" or "host"
	// for ssh -G; "" otherwise) and the log message to use.
	err     error
	errSide string
	errMsg  string
}

// planHostKeys decides what to do for one connect: ip check without logging,
// printing or connecting to anything (ssh -G and ssh-keygen -F on local
// files only), so `check` can reuse it to diagnose unknown-host-key
// failures. printed holds keys already printed this run by plain ip name,
// counted as recorded; nil means none.
func planHostKeys(ctx context.Context, c Check, env knownHostsEnv, printed map[string][]hostKey) hostKeyPlan {
	ipOut, err := env.sshConfig(ctx, c.Hostname, c.IP)
	if err != nil {
		return hostKeyPlan{status: hostKeyLookupError, err: err, errSide: "ip", errMsg: "ssh -G failed"}
	}
	ipSide := parseSSHConfig(ipOut)
	if alias := ipSide["hostkeyalias"]; alias != "" && alias != "none" {
		return hostKeyPlan{status: hostKeyAliased, ipName: alias}
	}
	hostOut, err := env.sshConfig(ctx, c.Hostname, "")
	if err != nil {
		return hostKeyPlan{status: hostKeyLookupError, err: err, errSide: "host", errMsg: "ssh -G failed"}
	}
	hostSide := parseSSHConfig(hostOut)
	// A host-side HostKeyAlias is the name ssh files the host's key under,
	// verbatim: no [ ]:port wrapping.
	p := hostKeyPlan{
		hostName: knownHostsName(hostSide["hostname"], hostSide["port"]),
		ipName:   knownHostsName(c.IP, ipSide["port"]),
		hash:     ipSide["hashknownhosts"] == "yes",
	}
	if alias := hostSide["hostkeyalias"]; alias != "" && alias != "none" {
		p.hostName = alias
	}

	// Each name is looked up in the files ssh consults for that side; they
	// differ when a file name uses %h.
	hostFiles, ipFiles := knownHostsFiles(hostSide), knownHostsFiles(ipSide)
	ipUser, hostUser := userKnownHostsFiles(ipSide), userKnownHostsFiles(hostSide)
	if len(ipUser) > 0 {
		p.ipUserFile = ipUser[0]
		p.userFilesDiffer = !slices.Equal(ipUser, hostUser)
	}

	hostKeys, hostRevoked, err := findKeys(ctx, env, p.hostName, hostFiles)
	if err != nil {
		p.status, p.err, p.errMsg = hostKeyLookupError, err, "looking up host key failed"
		return p
	}
	if len(hostKeys) == 0 {
		p.status = hostKeyNoHostKey
		return p
	}
	ipKeys, ipRevoked, err := findKeys(ctx, env, p.ipName, ipFiles)
	if err != nil {
		p.status, p.err, p.errMsg = hostKeyLookupError, err, "looking up ip key failed"
		return p
	}
	hostKeys = subtractKeys(subtractKeys(hostKeys, hostRevoked), ipRevoked)
	if len(hostKeys) == 0 {
		p.status = hostKeyRevoked
		return p
	}
	ipKeys = append(ipKeys, printed[p.ipName]...)
	for _, k := range ipKeys {
		if !slices.Contains(hostKeys, k) {
			p.status = hostKeyForeignIPKey
			return p
		}
	}
	for _, k := range hostKeys {
		if !slices.Contains(ipKeys, k) {
			p.add = append(p.add, k)
		}
	}
	p.status = hostKeyRecorded
	if len(p.add) > 0 {
		p.status = hostKeyAddable
	}
	return p
}

// knownHostsFor handles one connect: ip check: it plans (planHostKeys), logs
// per status, and prints the addable keys. It returns the number of lines
// printed, the ip side's first user known_hosts file (where they belong),
// and whether it went without a problem (already logged).
func knownHostsFor(ctx context.Context, c Check, env knownHostsEnv, log *slog.Logger,
	w io.Writer, printed map[string][]hostKey) (int, string, bool) {
	p := planHostKeys(ctx, c, env, printed)
	if p.userFilesDiffer {
		log.Warn("user known_hosts files differ between host and ip; the printed lines belong in the ip side's first user known_hosts file, not necessarily ~/.ssh/known_hosts",
			"hostname", c.Hostname, "ip", c.IP, "file", p.ipUserFile)
	}
	switch p.status {
	case hostKeyAliased:
		log.Debug("hostkeyalias set; ssh already verifies the ip against it, skipping",
			"hostname", c.Hostname, "ip", c.IP, "hostkeyalias", p.ipName)
		return 0, "", true
	case hostKeyLookupError:
		if p.errSide != "" {
			log.Error(p.errMsg, "side", p.errSide, "hostname", c.Hostname, "ip", c.IP, "err", p.err)
		} else {
			name := p.hostName
			if p.errMsg == "looking up ip key failed" {
				name = p.ipName
			}
			log.Error(p.errMsg, "hostname", c.Hostname, "ip", c.IP, "name", name, "err", p.err)
		}
		return 0, "", false
	case hostKeyNoHostKey:
		log.Error("no known host key for host; add it by hand, see README",
			"hostname", c.Hostname, "ip", c.IP, "name", p.hostName)
		return 0, "", false
	case hostKeyRevoked:
		log.Error("host key revoked for host; not adding",
			"hostname", c.Hostname, "ip", c.IP, "name", p.hostName)
		return 0, "", false
	case hostKeyForeignIPKey:
		log.Error("ip already has a different host key; not adding",
			"hostname", c.Hostname, "ip", c.IP, "name", p.ipName)
		return 0, "", false
	case hostKeyRecorded:
		log.Debug("already recorded", "hostname", c.Hostname, "ip", c.IP, "name", p.ipName)
		return 0, "", true
	}

	var n int
	for _, k := range p.add {
		field := p.ipName
		if p.hash {
			salt, err := env.salt()
			if err != nil {
				log.Error("generating salt failed", "hostname", c.Hostname, "ip", c.IP, "err", err)
				return n, p.ipUserFile, false
			}
			field = hashKnownHostsName(p.ipName, salt)
		}
		if _, err := fmt.Fprintf(w, "%s %s %s\n", field, k.typ, k.key); err != nil {
			log.Error("writing output", "err", err)
			return n, p.ipUserFile, false
		}
		printed[p.ipName] = append(printed[p.ipName], k)
		n++
	}
	return n, p.ipUserFile, true
}
