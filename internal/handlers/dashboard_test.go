package handlers

import (
	"testing"
	"time"

	"github.com/iulianfsdro/rpi-network-filter/internal/models"
)

// The Dashboard is about the Tesla: the device whose alias or hostname says so.
// Among several, an online one wins, then the most recently seen.
func TestPickTesla(t *testing.T) {
	now := time.Now()
	cases := []struct {
		name string
		devs []models.Device
		want string // MAC of the expected device; "" means nil
	}{
		{"no match", []models.Device{{MACAddress: "m1", Alias: "Laptop"}, {MACAddress: "m2", Hostname: "phone"}}, ""},
		{"alias match", []models.Device{{MACAddress: "m1", Alias: "tv"}, {MACAddress: "m2", Alias: "Model Y (garage)", Hostname: "tesla_y"}}, "m2"},
		{"case-insensitive", []models.Device{{MACAddress: "m1", Alias: "TESLA"}}, "m1"},
		{"hostname only", []models.Device{{MACAddress: "m1", Hostname: "Tesla-Model-3"}}, "m1"},
		{"online beats newer", []models.Device{
			{MACAddress: "m1", Alias: "tesla a", Online: false, LastSeen: now},
			{MACAddress: "m2", Alias: "tesla b", Online: true, LastSeen: now.Add(-time.Hour)},
		}, "m2"},
		{"both online: newest", []models.Device{
			{MACAddress: "m1", Alias: "tesla a", Online: true, LastSeen: now.Add(-time.Hour)},
			{MACAddress: "m2", Alias: "tesla b", Online: true, LastSeen: now},
		}, "m2"},
	}
	for _, c := range cases {
		got := pickTesla(c.devs)
		switch {
		case c.want == "" && got != nil:
			t.Errorf("%s: got %s, want nil", c.name, got.MACAddress)
		case c.want != "" && (got == nil || got.MACAddress != c.want):
			t.Errorf("%s: got %v, want %s", c.name, got, c.want)
		}
	}
}
