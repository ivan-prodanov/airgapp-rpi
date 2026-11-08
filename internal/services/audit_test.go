package services

import (
	"strings"
	"testing"
)

// A VIN never reaches the page, even from a row written before VINs stopped
// being logged.
func TestAuditRecent_ScrubsVINs(t *testing.T) {
	db := migratedDB(t)
	a := NewAuditService(db)
	a.Log("tesla.set_vin", "owner set VIN to 5YJ3E1EA7KF000001")
	a.Log("tesla.ble_session_open", "owner opened BLE session abc123 (vin=LRW3E7EK1NC000002)")
	got, err := a.Recent(10)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range got {
		if strings.Contains(e.Details, "5YJ3E1EA7KF000001") || strings.Contains(e.Details, "LRW3E7EK1NC000002") {
			t.Errorf("VIN in %q", e.Details)
		}
	}
	if got[0].Details != "owner opened BLE session abc123 (vin=[VIN])" {
		t.Errorf("newest first, scrubbed: %q", got[0].Details)
	}
}

// The activity row's summary: how many events, since when.
func TestAuditSummary(t *testing.T) {
	db := migratedDB(t)
	a := NewAuditService(db)
	mustExec(t, db, `DELETE FROM audit_log`)
	mustExec(t, db, `INSERT INTO audit_log (action, details, timestamp) VALUES ('a','x','2026-05-22 08:00:00'),('b','y','2026-06-01 09:00:00'),('c','z','2026-11-07 10:00:00')`)
	total, since, err := a.Summary()
	if err != nil || total != 3 || since != "2026-05-22 08:00:00" {
		t.Fatalf("Summary = %d %q %v", total, since, err)
	}
}
