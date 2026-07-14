package services

import "testing"

// TestAssistantCarveOut is the safety guard for the Grok feature: the
// narrow assistant exemption must NOT open any of the ban/telemetry
// channels under the vn.cloud.tesla.com apex (or anywhere else). If this
// test ever fails, the airgap is compromised — do not ship.
func TestAssistantCarveOut(t *testing.T) {
	// These MUST remain protected-denied after the carve-out.
	mustDeny := []string{
		"hermes-api.prd.eu.vn.cloud.tesla.com",
		"hermes-api.prd.na.vn.cloud.tesla.com",
		"hermes-stream-api.prd.eu.vn.cloud.tesla.com",
		"device-api.prd.eu.vn.cloud.tesla.com",
		"web-api.prd.eu.vn.cloud.tesla.com",
		"apf-api.prd.vn.cloud.tesla.com",
		"vn.cloud.tesla.com",
		"something-new.prd.eu.vn.cloud.tesla.com", // future regional service
		"mothership.vn.teslamotors.com",
		"telemetry-prd.ap.tesla.services",
		"hermes-prd.ap.tesla.services",
		// suffix-trick: a hermes host that merely contains the assistant
		// label must still be denied (the exempt map is exact-match only).
		"hermes-api.assistant-api.prd.euw1.vn.cloud.tesla.com",
	}
	for _, d := range mustDeny {
		if !isProtectedDenied(d) {
			t.Errorf("SAFETY BREACH: %q must be protected-denied but is NOT", d)
		}
	}

	// Only the exact assistant hosts are allow-able.
	mustAllow := []string{
		"assistant-api.prd.euw1.vn.cloud.tesla.com",
		"assistant-api.prd.na.vn.cloud.tesla.com",
		"assistant-api.prd.cnn1.vn.cloud.tesla.cn",
	}
	for _, d := range mustAllow {
		if isProtectedDenied(d) {
			t.Errorf("%q should be allow-able (Grok carve-out) but is denied", d)
		}
	}

	// The exempt set must be exactly the assistant hosts — nothing that
	// smells like hermes/device/etc.
	for d := range assistantExempt {
		if len(d) < len("assistant-api.") || d[:len("assistant-api.")] != "assistant-api." {
			t.Errorf("SAFETY: exempt host %q is not an assistant-api host", d)
		}
	}
}
