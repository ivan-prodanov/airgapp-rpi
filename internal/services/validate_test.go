package services

import (
	"errors"
	"strings"
	"testing"
)

func TestValidPresetName(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"Tesla AP/Nav", true}, // '/' allowed for service names
		{"Disney+", true},      // '+' allowed
		{"YouTube", true},
		{"Netflix", true},
		{"Kids tablet", true},
		{"preset_1", true},
		{"a-b-c", true},
		{"", false},
		{" leading", false},
		{"-dash-start", false},
		{"has\nnewline", false},
		{`has"quote`, false},
		{"drop] drop", false},             // nft log-prefix injection
		{"preset;drop table", false},      // SQL-adjacent junk
		{string(make([]byte, 65)), false}, // too long
	}
	for _, c := range cases {
		if got := ValidPresetName(c.in); got != c.want {
			t.Errorf("ValidPresetName(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestValidDomain(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"example.com", true},
		{"a.b.c.d.example.com", true},
		{"connman.vn.tesla.services", true},
		{"x.io", true},
		{"", false},
		{"localhost", true},
		{"ex ample.com", false},                      // space
		{"evil.com\nnftset=/bad/inet#filter", false}, // newline injection
		{"foo/bar", false},                           // slash breaks dnsmasq address=
		{"has#hash.com", false},
		{".leading-dot", false},
		{"trailing-dot.", false},
		{"-startshypen.com", false},
	}
	for _, c := range cases {
		if got := ValidDomain(c.in); got != c.want {
			t.Errorf("ValidDomain(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestValidIPv4(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"192.168.4.1", true},
		{"1.1.1.1", true},
		{"0.0.0.0", true},
		{"255.255.255.255", true},
		{"1.2.3.4 extra", false},
		{"::1", false},
		{"2606:4700:4700::1111", false},
		{"", false},
		{"1.2.3", false},
		{"1.2.3.4.5", false},
	}
	for _, c := range cases {
		if got := ValidIPv4(c.in); got != c.want {
			t.Errorf("ValidIPv4(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestValidMAC(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"aa:bb:cc:dd:ee:ff", true},
		{"AA:BB:CC:DD:EE:FF", true}, // lowercased internally
		{"4c:fc:aa:17:37:75", true},
		{"aa:bb:cc:dd:ee:gg", false},           // non-hex
		{"aa%3abb%3acc%3add%3aee%3aff", false}, // URL-encoded (v8 bug regression guard)
		{"aa-bb-cc-dd-ee-ff", false},           // wrong separator
		{"aabbccddeeff", false},                // missing separators
		{"aa:bb:cc:dd:ee", false},              // too short
		{"", false},
	}
	for _, c := range cases {
		if got := ValidMAC(c.in); got != c.want {
			t.Errorf("ValidMAC(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestSanitizeSingleLine(t *testing.T) {
	cases := []struct {
		in   string
		want string
	}{
		{"NetFilter", "NetFilter"},
		{"hello world", "hello world"},
		{"newline\nhere", "newlinehere"},
		{"cr\rhere", "crhere"},
		{"tab\there", "tabhere"},
		{"bell\x07here", "bellhere"},
		{"del\x7fhere", "delhere"},
		{"", ""},
	}
	for _, c := range cases {
		if got := SanitizeSingleLine(c.in); got != c.want {
			t.Errorf("SanitizeSingleLine(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestValidProtocol(t *testing.T) {
	for _, p := range []string{"", "all", "tcp", "udp", "icmp"} {
		if !ValidProtocol(p) {
			t.Errorf("ValidProtocol(%q) should be true", p)
		}
	}
	for _, p := range []string{"ftp", "TCP", "tcp;drop", "\n"} {
		if ValidProtocol(p) {
			t.Errorf("ValidProtocol(%q) should be false", p)
		}
	}
}

func TestValidPortSpec(t *testing.T) {
	good := []string{"", "22", "80", "8443", "1-65535", "80-443"}
	bad := []string{"abc", "22/tcp", "80;drop", "80 443", "1-2-3"}
	for _, s := range good {
		if !ValidPortSpec(s) {
			t.Errorf("ValidPortSpec(%q) should be true", s)
		}
	}
	for _, s := range bad {
		if ValidPortSpec(s) {
			t.Errorf("ValidPortSpec(%q) should be false", s)
		}
	}
}

func TestValidIPOrCIDR(t *testing.T) {
	good := []string{"", "192.168.4.1", "10.0.0.0/8", "172.16.0.0/12"}
	bad := []string{"1.2.3", "1.2.3.4/", "1.2.3.4/33", "foo"}
	for _, s := range good {
		if !ValidIPOrCIDR(s) {
			t.Errorf("ValidIPOrCIDR(%q) should be true", s)
		}
	}
	for _, s := range bad {
		if ValidIPOrCIDR(s) {
			t.Errorf("ValidIPOrCIDR(%q) should be false", s)
		}
	}
}

// The System page shows these messages as they are, on the field named by Key.
func TestValidateSettings(t *testing.T) {
	cases := []struct {
		name string
		in   map[string]string
		key  string // "" = valid
		msg  string
	}{
		{"all good", map[string]string{"ap_ssid": "Airgapp", "ap_password": "longenough", "ap_channel": "36", "ap_country": "BG", "dns_upstream": "1.1.1.1,9.9.9.9", "log_retention_days": "30"}, "", ""},
		{"password unchanged", map[string]string{"ap_ssid": "Airgapp", "ap_password": ""}, "", ""},
		{"unknown key", map[string]string{"admin": "x"}, "admin", `unknown setting "admin"`},
		{"empty ssid", map[string]string{"ap_ssid": "  "}, "ap_ssid", "Give the network a name."},
		{"emoji ssid over 32 bytes", map[string]string{"ap_ssid": "🔥🔥🔥🔥🔥🔥🔥🔥🔥"}, "ap_ssid", "Too long: 36 of 32 bytes. Emoji count as 4 each."},
		{"ssid 32 bytes", map[string]string{"ap_ssid": "abcdefghijabcdefghijabcdefghijab"}, "", ""},
		{"short password", map[string]string{"ap_password": "short"}, "ap_password", "The password needs 8 to 63 characters."},
		{"long password", map[string]string{"ap_password": strings.Repeat("x", 64)}, "ap_password", "The password needs 8 to 63 characters."},
		{"bad channel", map[string]string{"ap_channel": "13"}, "ap_channel", "Pick a channel the hotspot supports."},
		{"2.4 channel", map[string]string{"ap_channel": "11"}, "", ""},
		{"bad country", map[string]string{"ap_country": "BGR"}, "ap_country", "Use a two-letter country code."},
		{"no resolver", map[string]string{"dns_upstream": " "}, "dns_upstream", "Keep at least one resolver."},
		{"bad resolver", map[string]string{"dns_upstream": "1.1.1.1,dns.google"}, "dns_upstream", "dns.google isn't an IPv4 address like 9.9.9.9."},
		{"bad retention", map[string]string{"log_retention_days": "14"}, "log_retention_days", "Keep traffic for 7, 30 or 90 days."},
		{"retention 90", map[string]string{"log_retention_days": "90"}, "", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			err := ValidateSettings(c.in)
			if c.key == "" {
				if err != nil {
					t.Fatalf("want valid, got %v", err)
				}
				return
			}
			var se *SettingError
			if !errors.As(err, &se) || se.Key != c.key || se.Msg != c.msg {
				t.Fatalf("got %#v, want key %q msg %q", err, c.key, c.msg)
			}
		})
	}
}
