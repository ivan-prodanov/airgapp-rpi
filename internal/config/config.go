package config

import (
	"fmt"
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	ListenAddr     string `yaml:"listen_addr"`
	UseTLS         bool   `yaml:"use_tls"`
	TLSCert        string `yaml:"tls_cert"`
	TLSKey         string `yaml:"tls_key"`
	DBPath         string `yaml:"db_path"`
	WANInterface   string `yaml:"wan_interface"`
	LANInterface   string `yaml:"lan_interface"`
	LANSubnet      string `yaml:"lan_subnet"`
	LANGateway     string `yaml:"lan_gateway"`
	DHCPRangeStart string `yaml:"dhcp_range_start"`
	DHCPRangeEnd   string `yaml:"dhcp_range_end"`
	DNSUpstream    string `yaml:"dns_upstream"`
	SNIProxyPort   int    `yaml:"sni_proxy_port"`
	// EnrolHost is the hostname a LAN device (the car's browser, a phone on
	// the AP) types to reach the self-service enrol-QR page over plain HTTP —
	// no cert, no login. On the hotspot the Pi answers it with LANGateway
	// (dnsmasq, and for Open devices a DNS redirect for this one name) and
	// the :80 spoof server vhosts it. A real-looking name: browsers treat a
	// typed name with no real top-level domain as a search. The page stays
	// LAN-only: :80 is wlan0-bound and nothing publishes it.
	EnrolHost string `yaml:"enrol_host"`
	// EnrolAddr is what the enrol host resolves to on the hotspot: a public-
	// looking address the Pi intercepts (its web traffic is DNAT'd to the Pi),
	// because the car's browser won't connect to a private one. TEST-NET-3 is
	// never routed on the internet, so off the hotspot it goes nowhere.
	EnrolAddr string `yaml:"enrol_addr"`
	// ConsoleHost is the name typed in the car to open the console. On the
	// hotspot it resolves to EnrolAddr like the enrol host, and the :80 spoof
	// server answers it with a redirect to the console: Tailscale's address
	// for it (real certificate) when the Pi is on a tailnet, else the Pi's own.
	ConsoleHost string `yaml:"console_host"`
	// TailnetAddr is what the Pi's own tailnet name resolves to on the
	// hotspot: a second intercepted address whose console and Funnel ports
	// are forwarded to Tailscale on the Pi. It must differ from EnrolAddr,
	// whose :443 goes to the captive-check responder instead.
	TailnetAddr string `yaml:"tailnet_addr"`
	DryRun      bool   `yaml:"dry_run"`
	LogLevel    string `yaml:"log_level"`
}

func Defaults() Config {
	return Config{
		// Bind on all interfaces by default so Tailscale (tailscale0) can
		// reach the UI without the operator having to remember to
		// rewrite the address. Per-interface ACL lives in the firewall.
		ListenAddr:     ":80",
		UseTLS:         false,
		TLSCert:        "/etc/netfilterd/server.crt",
		TLSKey:         "/etc/netfilterd/server.key",
		DBPath:         "/var/lib/netfilterd/netfilter.db",
		WANInterface:   "eth1",
		LANInterface:   "wlan0",
		LANSubnet:      "192.168.4.0/24",
		LANGateway:     "192.168.4.1",
		DHCPRangeStart: "192.168.4.100",
		DHCPRangeEnd:   "192.168.4.250",
		DNSUpstream:    "1.1.1.1,8.8.8.8",
		SNIProxyPort:   8444,
		EnrolHost:      "airgapp.me",
		EnrolAddr:      "203.0.113.80",
		ConsoleHost:    "airgapp.net",
		TailnetAddr:    "203.0.113.81",
		DryRun:         false,
		LogLevel:       "info",
	}
}

func Load(path string) (Config, error) {
	cfg := Defaults()

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			applyEnvOverrides(&cfg)
			return cfg, nil
		}
		return cfg, fmt.Errorf("read config %s: %w", path, err)
	}

	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return cfg, fmt.Errorf("parse config %s: %w", path, err)
	}

	applyEnvOverrides(&cfg)
	return cfg, nil
}

func applyEnvOverrides(cfg *Config) {
	envMap := map[string]*string{
		"NETFILTER_LISTEN_ADDR":      &cfg.ListenAddr,
		"NETFILTER_TLS_CERT":         &cfg.TLSCert,
		"NETFILTER_TLS_KEY":          &cfg.TLSKey,
		"NETFILTER_DB_PATH":          &cfg.DBPath,
		"NETFILTER_WAN_INTERFACE":    &cfg.WANInterface,
		"NETFILTER_LAN_INTERFACE":    &cfg.LANInterface,
		"NETFILTER_ENROL_HOST":       &cfg.EnrolHost,
		"NETFILTER_ENROL_ADDR":       &cfg.EnrolAddr,
		"NETFILTER_CONSOLE_HOST":     &cfg.ConsoleHost,
		"NETFILTER_TAILNET_ADDR":     &cfg.TailnetAddr,
		"NETFILTER_LAN_SUBNET":       &cfg.LANSubnet,
		"NETFILTER_LAN_GATEWAY":      &cfg.LANGateway,
		"NETFILTER_DHCP_RANGE_START": &cfg.DHCPRangeStart,
		"NETFILTER_DHCP_RANGE_END":   &cfg.DHCPRangeEnd,
		"NETFILTER_DNS_UPSTREAM":     &cfg.DNSUpstream,
		"NETFILTER_LOG_LEVEL":        &cfg.LogLevel,
	}
	for env, ptr := range envMap {
		if v := os.Getenv(env); v != "" {
			*ptr = v
		}
	}
	if v := os.Getenv("NETFILTER_DRY_RUN"); v != "" {
		cfg.DryRun = strings.EqualFold(v, "true") || v == "1"
	}
}
