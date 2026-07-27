package services

import (
	"database/sql"
	"log"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/executor"
)

type Services struct {
	Auth       *AuthService
	Network    *NetworkService
	Firewall   *FirewallService
	DNS        *DNSService
	Bandwidth  *BandwidthService
	Hotspot    *HotspotService
	System     *SystemService
	Audit      *AuditService
	TrafficLog *TrafficLogService
	Filter     *FilterService
	Spoof      *SpoofService
	SNIProxy   *SNIProxyService
	Tesla      *TeslaService
	TeslaToken *TeslaTokenService
	BLESession *BLESessionService
	LockWatch  *LockWatchService
	Remote     *RemoteService
}

func New(db *sql.DB, exec *executor.Executor, cfg config.Config) *Services {
	audit := NewAuditService(db)
	trafficLog := NewTrafficLogService(db)
	filter := NewFilterService(db)
	network := NewNetworkService(db, cfg)
	tesla := NewTeslaService(db, audit)
	bleSession := NewBLESessionService(tesla)
	// VIN resolves lazily inside Open when empty, so an unconfigured Pi
	// still constructs cleanly and simply never attaches.
	lockWatch := NewLockWatchService(bleSession, "")

	firewall := NewFirewallService(db, exec, cfg)
	hotspot := NewHotspotService(db, exec)
	hotspot.SetFirewallGate(firewall.Verify, firewall.Apply)

	return &Services{
		Auth:       NewAuthService(db),
		Network:    network,
		Firewall:   firewall,
		DNS:        NewDNSService(db, exec, cfg),
		Bandwidth:  NewBandwidthService(db, exec, cfg),
		Hotspot:    hotspot,
		System:     NewSystemService(exec, cfg),
		Audit:      audit,
		TrafficLog: trafficLog,
		Filter:     filter,
		Spoof:      NewSpoofService(cfg, exec),
		SNIProxy:   NewSNIProxyService(cfg, db, trafficLog),
		Tesla:      tesla,
		TeslaToken: NewTeslaTokenService(db),
		BLESession: bleSession,
		LockWatch:  lockWatch,
		Remote:     NewRemoteService(),
	}
}

func (s *Services) ApplyAll() {
	if err := s.Firewall.Apply(); err != nil {
		log.Printf("[WARN] Failed to apply firewall rules: %v", err)
	}
	if err := s.DNS.Apply(); err != nil {
		log.Printf("[WARN] Failed to apply DNS config: %v", err)
	}
	if err := s.Bandwidth.Apply(); err != nil {
		log.Printf("[WARN] Failed to apply bandwidth limits: %v", err)
	}
	if err := s.Hotspot.Apply(); err != nil {
		log.Printf("[WARN] Failed to apply hotspot config: %v", err)
	}

	// PHASE 1 — OBSERVE ONLY. No enforcer is installed, so the watcher can
	// read and log the car's lock state but cannot move the radio.
	s.LockWatch.Start()
}
