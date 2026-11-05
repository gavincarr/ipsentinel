// Per-host configuration for ipsentinel: the -c/--config YAML file maps
// (unstripped) hostnames to settings — how ssh reaches the host (connect)
// and what counts as a pass (check).
package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"maps"
	"os"
	"slices"
	"strings"

	"gopkg.in/yaml.v3"
)

// Connect modes: how ssh reaches a host.
const (
	// connectSSHConfig sshes to the hostname as given, resolved via
	// ~/.ssh/config and DNS. The default.
	connectSSHConfig = "ssh_config"
	// connectIP sshes straight to the expected IP (-o HostName=<ip>), still
	// taking port, user, identity etc. from ~/.ssh/config.
	connectIP = "ip"
)

// connectModes lists the valid connect values (sorted, as error messages
// show them), for config validation.
var connectModes = []string{connectIP, connectSSHConfig}

// checkNone is the check that runs `true` and passes on ssh success alone.
const checkNone = "none"

// Defaults for hosts with no config entry, or an entry without the key.
// defaultConnect is only the fallback for an empty Config.ConnectDefault:
// --connect-default (whose own default is ip) normally supplies it.
const (
	defaultConnect = connectIP
	defaultCheck   = "iproute2"
)

// awsCommand runs `ip address` and appends the instance's public IPv4 from
// the EC2 Instance Metadata Service (IMDSv2 with IMDSv1 fallback: no token =>
// header omitted). EC2 public IPs are 1:1 NAT mappings held in AWS
// infrastructure, not configured on the instance, so they never appear in
// `ip address` output. curl failures are tolerated (|| true) so an IMDS
// hiccup or missing curl degrades to plain `ip address` matching rather than
// an ssh error; -m 2 caps each curl well inside the overall ssh timeout.
const awsCommand = `ip address
TOKEN=$(curl -sf -m 2 -X PUT -H "X-aws-ec2-metadata-token-ttl-seconds: 60" http://169.254.169.254/latest/api/token 2>/dev/null) || true
curl -sf -m 2 ${TOKEN:+-H "X-aws-ec2-metadata-token: $TOKEN"} http://169.254.169.254/latest/meta-data/public-ipv4 || true`

// ifconfigCommand is the non-AWS counterpart to awsCommand: it runs
// `ip address` and appends the host's public addresses as seen by
// ifconfig.me. Hosts behind a NAT gateway never have their public address
// configured on an interface, so asking an external echo service is the only
// way to see it.
//
// It queries both families (curl -4, then curl -6) rather than letting curl
// pick one: a dual-stack host, or one with both A and AAAA records, may be
// checked for either family, and verifyOutput just looks for the expected IP
// anywhere in the output, so one fixed command serves every ifconfig host
// and gives each the same authorized_keys forced command. `|| true` tolerates
// a family the host lacks — curl -6 on an IPv4-only host normally fails fast
// with "network unreachable", worst case after the -m 2 cap, which keeps both
// requests well inside the overall ssh timeout — and any other curl failure,
// so the check degrades to plain `ip address` matching. Each `echo` supplies
// the newline curl's response body lacks, keeping the two answers apart.
// Every line is a complete command, as forcedCommand's "; " join requires.
const ifconfigCommand = `ip address
curl -sf -4 -m 2 https://ifconfig.me || true
echo
curl -sf -6 -m 2 https://ifconfig.me || true
echo`

// checkCommands maps a check name to the remote command ssh runs on the
// target host. It is the single source of truth for known checks: config
// validation checks `check` values against these keys, and authorized-keys
// forces exactly these commands.
//
// none runs `true` and its output is never read: the check is the ssh
// connection itself, which only proves anything with connect: ip (see
// loadConfig). `true` is also the least capability the monitoring key can
// be given as an authorized_keys forced command.
var checkCommands = map[string]string{
	"iproute2": "ip address",
	"aws":      awsCommand,
	"ifconfig": ifconfigCommand,
	checkNone:  "true",
}

// HostConfig holds the per-host settings from the -c/--config file. Empty
// fields take their defaults via connectMode and checkName.
type HostConfig struct {
	Connect string `yaml:"connect"`
	Check   string `yaml:"check"`
}

// Config is everything that resolves a host's settings: the -c/--config
// entries (Hosts, keyed by unstripped hostname; nil without -c) and the
// --connect-default for hosts that don't set connect. The zero Config gives
// every host the built-in defaults.
type Config struct {
	Hosts          map[string]HostConfig
	ConnectDefault string // "" means defaultConnect
}

// check returns the Check for host with settings hc (the zero HostConfig
// for a host absent from config), resolving connect and check against their
// defaults. IP is left for the caller.
func (cfg Config) check(host string, hc HostConfig) Check {
	return Check{Hostname: host, Connect: hc.connectMode(cfg.ConnectDefault), CheckName: hc.checkName()}
}

// rawHostConfig is what loadConfig decodes each host entry into: HostConfig
// plus retired keys that are still recognised, solely so loadConfig can
// reject them with an actionable message instead of yaml's generic "field
// not found" error.
type rawHostConfig struct {
	HostConfig `yaml:",inline"`
	// IPVersion is the retired ip_version key, which used to force the
	// ifconfig curl to one family. A yaml.Node so that its presence is seen
	// whatever its value, even null.
	IPVersion yaml.Node `yaml:"ip_version"`
	// Type is the retired type key, which conflated connect and check. A
	// yaml.Node for the same reason as IPVersion, and so its value can
	// tailor the migration hint.
	Type yaml.Node `yaml:"type"`
}

// connectMode returns hc's connect mode, defaulting to connectDefault (the
// --connect-default value) when unset, including for the zero HostConfig of
// a host absent from config. An empty connectDefault means defaultConnect.
func (hc HostConfig) connectMode(connectDefault string) string {
	switch {
	case hc.Connect != "":
		return hc.Connect
	case connectDefault != "":
		return connectDefault
	}
	return defaultConnect
}

// checkName returns hc's check, defaulting to defaultCheck when unset
// (including for the zero HostConfig of a host absent from config).
func (hc HostConfig) checkName() string {
	if hc.Check == "" {
		return defaultCheck
	}
	return hc.Check
}

// typeMigrationHint says what to write instead of a retired `type: <value>`.
func typeMigrationHint(n yaml.Node) string {
	if n.Kind == yaml.ScalarNode {
		switch n.Value {
		case "iproute2", "aws", "ifconfig":
			return "use check: " + n.Value
		case "connect":
			return "use connect: ip and check: none"
		}
	}
	return "replace type with check (and connect)"
}

// loadConfig reads the YAML config file at path: a map keyed by (unstripped)
// hostname with per-host settings, returned as a Config with connectDefault
// (the --connect-default value) as its ConnectDefault. Unknown second-level keys, unknown
// connect or check values, retired keys, and check: none without
// connect: ip (explicit, or via connectDefault) are errors, so mistakes fail loudly at startup rather than
// silently checking the wrong thing. Hosts are validated in sorted order so
// the error for a config with several problems is deterministic.
func loadConfig(path, connectDefault string) (Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	raw := make(map[string]rawHostConfig)
	if err := dec.Decode(&raw); err != nil {
		if errors.Is(err, io.EOF) {
			return Config{Hosts: map[string]HostConfig{}, ConnectDefault: connectDefault}, nil // empty config file
		}
		return Config{}, fmt.Errorf("parsing %s: %w", path, err)
	}
	hosts := make(map[string]HostConfig, len(raw))
	for _, host := range slices.Sorted(maps.Keys(raw)) {
		rhc := raw[host]
		if !rhc.IPVersion.IsZero() {
			return Config{}, fmt.Errorf("%s: host %s: ip_version is no longer supported: "+
				"ifconfig checks now query both IPv4 and IPv6; remove it", path, host)
		}
		if !rhc.Type.IsZero() {
			return Config{}, fmt.Errorf("%s: host %s: type is no longer supported: %s",
				path, host, typeMigrationHint(rhc.Type))
		}
		hc := rhc.HostConfig
		if hc.Connect != "" && !slices.Contains(connectModes, hc.Connect) {
			return Config{}, fmt.Errorf("%s: host %s: unknown connect %q (known: %s)",
				path, host, hc.Connect, strings.Join(connectModes, ", "))
		}
		if _, ok := checkCommands[hc.Check]; hc.Check != "" && !ok {
			return Config{}, fmt.Errorf("%s: host %s: unknown check %q (known: %s)",
				path, host, hc.Check, strings.Join(slices.Sorted(maps.Keys(checkCommands)), ", "))
		}
		// check: none passes on ssh success alone, which only tests the IP
		// when ssh dials the IP itself.
		if connect := hc.connectMode(connectDefault); hc.checkName() == checkNone && connect != connectIP {
			from := "connect: " + connect
			if hc.Connect == "" {
				from = "connect unset, so --connect-default=" + connect + " applies"
			}
			return Config{}, fmt.Errorf("%s: host %s: check: none requires connect: ip "+
				"(%s; it would pass whenever ssh to the name works, without ever testing the IP)",
				path, host, from)
		}
		hosts[host] = hc
	}
	return Config{Hosts: hosts, ConnectDefault: connectDefault}, nil
}
