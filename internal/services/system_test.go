package services

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/executor"
)

// fakeRoot writes the files Vitals reads under a temp root.
func fakeRoot(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()
	for p, body := range files {
		full := filepath.Join(root, p)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

var piFiles = map[string]string{
	"proc/uptime":                            "622.40 2400.10\n",
	"proc/loadavg":                           "0.19 0.21 0.18 1/310 4242\n",
	"proc/meminfo":                           "MemTotal:        3884000 kB\nMemFree:          100000 kB\nMemAvailable:    3620000 kB\n",
	"sys/class/thermal/thermal_zone0/temp":   "32600\n",
	"sys/class/net/usb0/statistics/rx_bytes": "972119\n",
	"sys/class/net/usb0/statistics/tx_bytes": "1426105\n",
	"proc/device-tree/model":                 "Raspberry Pi 4 Model B Rev 1.4\x00",
	"etc/os-release":                         "PRETTY_NAME=\"Debian GNU/Linux 13 (trixie)\"\nNAME=\"Debian GNU/Linux\"\nVERSION_ID=\"13\"\nID=debian\n",
}

func TestVitals(t *testing.T) {
	s := NewSystemService(executor.New(true), config.Config{WANInterface: "usb0", LANGateway: "192.168.4.1"})
	s.root = fakeRoot(t, piFiles)
	v := s.Vitals()
	if v.UptimeS != 622 || v.Load1 != 0.19 {
		t.Errorf("uptime %d load %v", v.UptimeS, v.Load1)
	}
	if v.TempC == nil || *v.TempC != 32.6 {
		t.Errorf("temp %v, want 32.6", v.TempC)
	}
	if v.MemTotal != 3884000*1024 || v.MemUsed != (3884000-3620000)*1024 {
		t.Errorf("mem %d of %d", v.MemUsed, v.MemTotal)
	}
	if v.WanRx != 972119 || v.WanTx != 1426105 || v.WanIf != "usb0" || v.LanIP != "192.168.4.1" {
		t.Errorf("wan %d/%d %q lan %q", v.WanRx, v.WanTx, v.WanIf, v.LanIP)
	}
	if v.Model != "Raspberry Pi 4 Model B" || v.OS != "Debian 13" {
		t.Errorf("model %q os %q", v.Model, v.OS)
	}
	if v.DiskTotal == 0 || v.DiskUsed > v.DiskTotal {
		t.Errorf("disk %d of %d", v.DiskUsed, v.DiskTotal)
	}
}

// Without a thermal sensor the temperature is unknown, not zero.
func TestVitals_NoThermal(t *testing.T) {
	files := map[string]string{}
	for k, v := range piFiles {
		if k != "sys/class/thermal/thermal_zone0/temp" {
			files[k] = v
		}
	}
	s := NewSystemService(executor.New(true), config.Config{WANInterface: "usb0"})
	s.root = fakeRoot(t, files)
	if v := s.Vitals(); v.TempC != nil {
		t.Fatalf("temp %v, want nil", *v.TempC)
	}
}
