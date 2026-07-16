package main

import (
	"strings"
	"testing"
)

// captureAlerter records alerts for assertions in tests.
type captureAlerter struct {
	alerts []struct {
		check  Check
		reason string
	}
}

func (a *captureAlerter) Alert(c Check, reason string, _ error) {
	a.alerts = append(a.alerts, struct {
		check  Check
		reason string
	}{c, reason})
}

func TestParseInput(t *testing.T) {
	input := strings.Join([]string{
		"# a comment",
		"",
		"  host1 , 10.0.0.1 ", // whitespace trimmed
		"host2,10.0.0.2",
		"badline-no-comma",                      // malformed: no comma
		"host3,",                                // malformed: empty ip
		",10.0.0.4",                             // malformed: empty host
		"-oProxyCommand=touch /pwned,10.0.0.5",  // flag smuggling: leading dash
		"host;rm -rf,10.0.0.6",                  // invalid: shell metachars
		"sub.host_alias-1.example.com,10.0.0.7", // valid dotted/underscore/dash alias
	}, "\n")

	var alerter captureAlerter
	checks, failures := parseInput(strings.NewReader(input), &alerter, false, "")

	wantChecks := []Check{
		{"host1", "10.0.0.1"},
		{"host2", "10.0.0.2"},
		{"sub.host_alias-1.example.com", "10.0.0.7"},
	}
	if len(checks) != len(wantChecks) {
		t.Fatalf("got %d checks, want %d: %+v", len(checks), len(wantChecks), checks)
	}
	for i, want := range wantChecks {
		if checks[i] != want {
			t.Errorf("check[%d] = %+v, want %+v", i, checks[i], want)
		}
	}

	// 5 malformed/invalid lines: no-comma, empty ip, empty host, and two
	// invalid hostnames (leading dash + shell metachars).
	const wantFailures = 5
	if failures != wantFailures {
		t.Errorf("got %d failures, want %d", failures, wantFailures)
	}
	if len(alerter.alerts) != wantFailures {
		t.Errorf("got %d alerts, want %d", len(alerter.alerts), wantFailures)
	}
}

func TestParseInputRejectsFlagSmuggling(t *testing.T) {
	var alerter captureAlerter
	checks, failures := parseInput(strings.NewReader("-oProxyCommand=evil,10.0.0.1\n"), &alerter, false, "")

	if len(checks) != 0 {
		t.Fatalf("flag-smuggling host was accepted as a check: %+v", checks)
	}
	if failures != 1 {
		t.Errorf("got %d failures, want 1", failures)
	}
	if len(alerter.alerts) != 1 || alerter.alerts[0].reason != "invalid hostname" {
		t.Errorf("expected one 'invalid hostname' alert, got %+v", alerter.alerts)
	}
}

func TestStripHostname(t *testing.T) {
	tests := []struct {
		in, want string
	}{
		{"foo.example.com", "foo"},
		{"a.b.example.com", "a"},
		{"host", "host"},
		{"", ""},
	}
	for _, tt := range tests {
		if got := stripHostname(tt.in); got != tt.want {
			t.Errorf("stripHostname(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}

func TestParseInputStrip(t *testing.T) {
	input := "foo.example.com,10.0.0.1\nbar,10.0.0.2\n"

	// stripAll=true reduces each validated hostname to its leftmost label.
	var alerter captureAlerter
	checks, failures := parseInput(strings.NewReader(input), &alerter, true, "")
	wantStripped := []Check{{"foo", "10.0.0.1"}, {"bar", "10.0.0.2"}}
	if failures != 0 {
		t.Fatalf("got %d failures, want 0", failures)
	}
	if len(checks) != len(wantStripped) {
		t.Fatalf("got %d checks, want %d: %+v", len(checks), len(wantStripped), checks)
	}
	for i, want := range wantStripped {
		if checks[i] != want {
			t.Errorf("strip=true check[%d] = %+v, want %+v", i, checks[i], want)
		}
	}

	// stripAll=false leaves the hostname untouched (existing behaviour).
	var alerter2 captureAlerter
	checks, _ = parseInput(strings.NewReader(input), &alerter2, false, "")
	if checks[0].Hostname != "foo.example.com" {
		t.Errorf("stripAll=false altered hostname: got %q, want %q", checks[0].Hostname, "foo.example.com")
	}
}

func TestStripDomain(t *testing.T) {
	tests := []struct {
		host, domain, want string
	}{
		{"foo.example.com", "example.com", "foo"},           // leading dot added
		{"foo.example.com", ".example.com", "foo"},          // leading dot already present
		{"a.b.example.com", "example.com", "a.b"},           // only the suffix is removed
		{"foo.example.com", "other.com", "foo.example.com"}, // suffix absent: unchanged
		{"example.com", "example.com", "example.com"},       // no leading label: unchanged
		{"foo", "example.com", "foo"},                       // bare host: unchanged
	}
	for _, tt := range tests {
		if got := stripDomain(tt.host, tt.domain); got != tt.want {
			t.Errorf("stripDomain(%q, %q) = %q, want %q", tt.host, tt.domain, got, tt.want)
		}
	}
}

func TestParseInputStripDomain(t *testing.T) {
	input := "foo.example.com,10.0.0.1\nbar.other.com,10.0.0.2\nbaz,10.0.0.3\n"

	// domain suffix is stripped only where it matches; other hosts pass through.
	var alerter captureAlerter
	checks, failures := parseInput(strings.NewReader(input), &alerter, false, "example.com")
	want := []Check{{"foo", "10.0.0.1"}, {"bar.other.com", "10.0.0.2"}, {"baz", "10.0.0.3"}}
	if failures != 0 {
		t.Fatalf("got %d failures, want 0", failures)
	}
	if len(checks) != len(want) {
		t.Fatalf("got %d checks, want %d: %+v", len(checks), len(want), checks)
	}
	for i, w := range want {
		if checks[i] != w {
			t.Errorf("check[%d] = %+v, want %+v", i, checks[i], w)
		}
	}
}

func TestIPPresent(t *testing.T) {
	// Representative `ip address` output.
	out := `2: eth0: <BROADCAST,MULTICAST,UP,LOWER_UP> mtu 1500
    inet 10.0.0.1/24 brd 10.0.0.255 scope global eth0
    inet6 fe80::1/64 scope link`

	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"present ipv4", "10.0.0.1", true},
		{"present ipv6", "fe80::1", true},
		{"broadcast address also matches", "10.0.0.255", true},
		{"absent", "192.168.1.1", false},
		{"substring trap not a false match", "10.0.0.10", false},
		{"prefix substring not a false match", "10.0.0", false},
		{"empty", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ipPresent(out, tt.ip); got != tt.want {
				t.Errorf("ipPresent(out, %q) = %v, want %v", tt.ip, got, tt.want)
			}
		})
	}
}

func TestValidHostname(t *testing.T) {
	valid := []string{"host", "host1", "sub.example.com", "my_host-1", "10.0.0.1"}
	invalid := []string{"", "-oProxyCommand", "-h", "host;rm", "a b", "host/../x", "café"}

	for _, h := range valid {
		if !validHostname.MatchString(h) {
			t.Errorf("validHostname rejected valid hostname %q", h)
		}
	}
	for _, h := range invalid {
		if validHostname.MatchString(h) {
			t.Errorf("validHostname accepted invalid hostname %q", h)
		}
	}
}
