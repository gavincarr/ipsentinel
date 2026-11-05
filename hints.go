package main

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"sync"
)

// reasonHostKeyNotRecorded is the alert reason for a connect: ip check whose
// host key isn't recorded under the ip name yet: the expected state on a
// first run, and fixable, unlike a changed key.
const reasonHostKeyNotRecorded = "host key not recorded for ip"

// firstRunMinFailures and the 2*N >= M rule in logHostKeyHints decide when a
// run looks like a first run, worth suggesting --connect-default=ssh_config.
const firstRunMinFailures = 3

// unknownHostKey reports whether err is ssh refusing a host whose key it has
// no record of, as opposed to a changed, revoked or mismatched key. ssh says
// "Host key verification failed" for all of them, but wraps most alarms in
// an @@@ banner and never an unknown key. The exception is a server
// presenting a key of a different type from the one recorded (a possible
// downgrade): OpenSSH prints no banner, only "WARNING: ED25519 key found for
// host ..." or "... but keys of different type are already known". Those two
// phrases are alarms too, so they count as known keys, not unknown ones.
func unknownHostKey(err error) bool {
	if err == nil {
		return false
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "host key verification failed") {
		return false
	}
	for _, alarm := range []string{"@@@", "key found for host", "keys of different type are already known"} {
		if strings.Contains(msg, alarm) {
			return false
		}
	}
	return true
}

// unknownKeyChecks collects, concurrently, the checks alerted as unknown
// host keys, for the closing hint.
type unknownKeyChecks struct {
	mu     sync.Mutex
	checks []Check
}

func (u *unknownKeyChecks) add(c Check) {
	u.mu.Lock()
	u.checks = append(u.checks, c)
	u.mu.Unlock()
}

// shellQuote single-quotes s unless it only has characters that are safe
// unquoted in a shell word.
func shellQuote(s string) string {
	safe := s != ""
	for _, r := range s {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' ||
			strings.ContainsRune("._/:=@+-", r)) {
			safe = false
			break
		}
	}
	if safe {
		return s
	}
	return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'"
}

// knownHostsCommand returns the known-hosts command line to suggest,
// echoing the user's own relevant flags (never check-only ones like -i) so
// it can be pasted as is.
func knownHostsCommand(cli CLI) string {
	parts := []string{"ipsentinel known-hosts"}
	if cli.Config != "" {
		parts = append(parts, "-c "+shellQuote(cli.Config))
	}
	if cli.ConnectDefault != "" && cli.ConnectDefault != defaultConnect {
		parts = append(parts, "--connect-default="+shellQuote(cli.ConnectDefault))
	}
	switch {
	case cli.Check.StripAll:
		parts = append(parts, "-S")
	case cli.Check.Strip != "":
		parts = append(parts, "-s "+shellQuote(cli.Check.Strip))
	}
	return strings.Join(parts, " ")
}

// logHostKeyHints closes a check run with an explanation of the unknown host
// key failures, so a new user's wall of alerts has a next step. unknown are
// the checks alerted as unknown host keys and total the connect: ip checks
// in the run. Each unknown check is diagnosed with the same local-only logic
// as `known-hosts` (nothing is connected to): fixable by known-hosts, having
// no known key at all, or something else, which gets no line of its own.
func logHostKeyHints(ctx context.Context, cli CLI, unknown []Check, total int, log *slog.Logger, env knownHostsEnv) {
	n := len(unknown)
	if n == 0 {
		return
	}
	var fixable, noKey int
	files := make(map[string]bool)
	for _, c := range unknown {
		switch p := planHostKeys(ctx, c, env, nil); p.status {
		case hostKeyAddable:
			fixable++
			files[p.ipUserFile] = true
		case hostKeyNoHostKey:
			noKey++
		}
	}

	log.Warn(fmt.Sprintf("%d of %d connect: ip hosts failed: host key not recorded under the ip yet", n, total))
	if fixable > 0 {
		cmd := knownHostsCommand(cli)
		if len(files) == 1 && !files[""] {
			for f := range files {
				cmd += " >> " + shellQuote(f)
			}
		} else {
			cmd += " and append its output to your known_hosts"
		}
		log.Warn(fmt.Sprintf("%d can be fixed with: %s", fixable, cmd))
	}
	if noKey > 0 {
		log.Warn(fmt.Sprintf(`%d have no known key at all; add them by hand, see README "connect: ip"`, noKey))
	}
	if n >= firstRunMinFailures && 2*n >= total {
		log.Warn("to check by hostname instead, pass --connect-default=ssh_config")
	}
}
