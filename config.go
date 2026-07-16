// Per-host configuration for ipsentinel: the -c/--config YAML file maps
// (unstripped) hostnames to settings — currently just the check type.
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

// defaultCheckType is used for hosts with no config entry or an empty type.
const defaultCheckType = "iproute2"

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

// checkCommands maps a check type to the remote command ssh runs on the
// target host. It is the single source of truth for known types: config
// validation checks `type` values against these keys.
var checkCommands = map[string]string{
	"iproute2": "ip address",
	"aws":      awsCommand,
}

// HostConfig holds the per-host settings from the -c/--config file.
type HostConfig struct {
	Type string `yaml:"type"`
}

// loadConfig reads the YAML config file at path: a map keyed by (unstripped)
// hostname with per-host settings. Unknown second-level keys and unknown
// type values are errors, so typos fail loudly at startup rather than
// silently checking the wrong thing.
func loadConfig(path string) (map[string]HostConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	config := make(map[string]HostConfig)
	if err := dec.Decode(&config); err != nil {
		if errors.Is(err, io.EOF) {
			return config, nil // empty config file
		}
		return nil, fmt.Errorf("parsing %s: %w", path, err)
	}
	for host, hc := range config {
		if hc.Type == "" {
			continue // defaults to defaultCheckType at lookup time
		}
		if _, ok := checkCommands[hc.Type]; !ok {
			return nil, fmt.Errorf("%s: host %s: unknown type %q (known: %s)",
				path, host, hc.Type, strings.Join(slices.Sorted(maps.Keys(checkCommands)), ", "))
		}
	}
	return config, nil
}
