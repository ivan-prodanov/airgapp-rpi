package services

import (
	"fmt"
	"math"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"syscall"

	"github.com/iulianfsdro/rpi-network-filter/internal/config"
	"github.com/iulianfsdro/rpi-network-filter/internal/executor"
)

type SystemService struct {
	exec *executor.Executor
	cfg  config.Config
	root string // filesystem root for /proc, /sys and /etc; tests use a fake tree
}

type SystemInfo struct {
	Uptime       string `json:"uptime"`
	LoadAvg      string `json:"load_avg"`
	MemTotal     string `json:"mem_total"`
	MemFree      string `json:"mem_free"`
	MemUsed      string `json:"mem_used"`
	WANInterface string `json:"wan_interface"`
	LANInterface string `json:"lan_interface"`
	WANIP        string `json:"wan_ip"`
	LANIP        string `json:"lan_ip"`
	WANRxBytes   string `json:"wan_rx_bytes"`
	WANTxBytes   string `json:"wan_tx_bytes"`
}

func NewSystemService(exec *executor.Executor, cfg config.Config) *SystemService {
	return &SystemService{exec: exec, cfg: cfg, root: "/"}
}

func (s *SystemService) GetInfo() SystemInfo {
	info := SystemInfo{
		WANInterface: s.cfg.WANInterface,
		LANInterface: s.cfg.LANInterface,
		LANIP:        s.cfg.LANGateway,
	}

	// Uptime
	if data, err := os.ReadFile("/proc/uptime"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) > 0 {
			info.Uptime = fields[0] + "s"
		}
	}

	// Load average
	if data, err := os.ReadFile("/proc/loadavg"); err == nil {
		fields := strings.Fields(string(data))
		if len(fields) >= 3 {
			info.LoadAvg = strings.Join(fields[:3], " ")
		}
	}

	// Memory
	if data, err := os.ReadFile("/proc/meminfo"); err == nil {
		memMap := parseMeminfo(string(data))
		info.MemTotal = memMap["MemTotal"]
		info.MemFree = memMap["MemAvailable"]
		if info.MemFree == "" {
			info.MemFree = memMap["MemFree"]
		}
	}

	// WAN IP
	if result, err := s.exec.Run("ip", "-4", "-o", "addr", "show", s.cfg.WANInterface); err == nil {
		fields := strings.Fields(result.Stdout)
		for i, f := range fields {
			if f == "inet" && i+1 < len(fields) {
				info.WANIP = strings.Split(fields[i+1], "/")[0]
				break
			}
		}
	}

	// WAN traffic stats
	info.WANRxBytes = readStat(s.cfg.WANInterface, "rx_bytes")
	info.WANTxBytes = readStat(s.cfg.WANInterface, "tx_bytes")

	return info
}

// Vitals is the System page's live readout of the Pi itself.
type Vitals struct {
	UptimeS   int64    `json:"uptime_s"`
	TempC     *float64 `json:"temp_c"` // nil without a thermal sensor
	Load1     float64  `json:"load1"`
	MemUsed   uint64   `json:"mem_used"`
	MemTotal  uint64   `json:"mem_total"`
	DiskUsed  uint64   `json:"disk_used"`
	DiskTotal uint64   `json:"disk_total"`
	WanRx     uint64   `json:"wan_rx"` // byte counters; the page turns them into rates
	WanTx     uint64   `json:"wan_tx"`
	WanIf     string   `json:"wan_if"`
	WanIP     string   `json:"wan_ip"`
	LanIP     string   `json:"lan_ip"`
	Model     string   `json:"model"`
	OS        string   `json:"os"`
}

func (s *SystemService) read(path string) string {
	b, err := os.ReadFile(filepath.Join(s.root, path))
	if err != nil {
		return ""
	}
	return strings.TrimSpace(strings.TrimRight(string(b), "\x00"))
}

var revSuffix = regexp.MustCompile(`\s+Rev\s+[0-9.]+$`)

// Vitals reads uptime, temperature, load, memory, storage and the WAN counters.
// Anything unreadable is left at its zero value (the temperature at nil).
func (s *SystemService) Vitals() Vitals {
	v := Vitals{WanIf: s.cfg.WANInterface, LanIP: s.cfg.LANGateway}
	if f := strings.Fields(s.read("proc/uptime")); len(f) > 0 {
		up, _ := strconv.ParseFloat(f[0], 64)
		v.UptimeS = int64(up)
	}
	if f := strings.Fields(s.read("proc/loadavg")); len(f) > 0 {
		v.Load1, _ = strconv.ParseFloat(f[0], 64)
	}
	kb := func(m map[string]string, k string) uint64 {
		n, _ := strconv.ParseUint(strings.TrimSuffix(strings.TrimSpace(m[k]), " kB"), 10, 64)
		return n * 1024
	}
	mem := parseMeminfo(s.read("proc/meminfo"))
	v.MemTotal = kb(mem, "MemTotal")
	avail := kb(mem, "MemAvailable")
	if avail == 0 {
		avail = kb(mem, "MemFree")
	}
	if v.MemTotal >= avail {
		v.MemUsed = v.MemTotal - avail
	}
	if t := s.read("sys/class/thermal/thermal_zone0/temp"); t != "" {
		if milli, err := strconv.ParseFloat(t, 64); err == nil {
			c := math.Round(milli/100) / 10
			v.TempC = &c
		}
	}
	var st syscall.Statfs_t
	if err := syscall.Statfs(s.root, &st); err == nil {
		bs := uint64(st.Bsize)
		v.DiskTotal = uint64(st.Blocks) * bs
		v.DiskUsed = (uint64(st.Blocks) - uint64(st.Bfree)) * bs
	}
	if s.cfg.WANInterface != "" {
		v.WanRx, _ = strconv.ParseUint(s.read("sys/class/net/"+s.cfg.WANInterface+"/statistics/rx_bytes"), 10, 64)
		v.WanTx, _ = strconv.ParseUint(s.read("sys/class/net/"+s.cfg.WANInterface+"/statistics/tx_bytes"), 10, 64)
		v.WanIP = s.wanIP()
	}
	v.Model = revSuffix.ReplaceAllString(s.read("proc/device-tree/model"), "")
	osr := map[string]string{}
	for _, line := range strings.Split(s.read("etc/os-release"), "\n") {
		if k, val, ok := strings.Cut(line, "="); ok {
			osr[k] = strings.Trim(val, `"`)
		}
	}
	if name := strings.Fields(osr["NAME"]); len(name) > 0 && osr["VERSION_ID"] != "" {
		v.OS = name[0] + " " + osr["VERSION_ID"]
	} else {
		v.OS = osr["PRETTY_NAME"]
	}
	return v
}

// wanIP is the WAN interface's IPv4 address, from `ip`.
func (s *SystemService) wanIP() string {
	result, err := s.exec.Run("ip", "-4", "-o", "addr", "show", s.cfg.WANInterface)
	if err != nil {
		return ""
	}
	fields := strings.Fields(result.Stdout)
	for i, f := range fields {
		if f == "inet" && i+1 < len(fields) {
			return strings.Split(fields[i+1], "/")[0]
		}
	}
	return ""
}

func (s *SystemService) Reboot() error {
	_, err := s.exec.Run("systemctl", "reboot")
	return err
}

type ConnectivityResult struct {
	Host    string `json:"host"`
	Success bool   `json:"success"`
	Latency string `json:"latency"`
	Error   string `json:"error,omitempty"`
}

func (s *SystemService) TestConnectivity() []ConnectivityResult {
	hosts := []string{"1.1.1.1", "8.8.8.8", "google.com"}
	results := make([]ConnectivityResult, 0, len(hosts))

	for _, host := range hosts {
		r := ConnectivityResult{Host: host}
		result, err := s.exec.Run("ping", "-c", "1", "-W", "3", host)
		if err != nil {
			r.Success = false
			r.Error = err.Error()
		} else {
			r.Success = true
			// Extract latency from ping output
			for _, line := range strings.Split(result.Stdout, "\n") {
				if strings.Contains(line, "time=") {
					parts := strings.Split(line, "time=")
					if len(parts) > 1 {
						r.Latency = strings.Fields(parts[1])[0]
					}
				}
			}
		}
		results = append(results, r)
	}
	return results
}

func readStat(iface, stat string) string {
	path := fmt.Sprintf("/sys/class/net/%s/statistics/%s", iface, stat)
	data, err := os.ReadFile(path)
	if err != nil {
		return "0"
	}
	return strings.TrimSpace(string(data))
}

func parseMeminfo(data string) map[string]string {
	result := make(map[string]string)
	for _, line := range strings.Split(data, "\n") {
		parts := strings.SplitN(line, ":", 2)
		if len(parts) == 2 {
			result[strings.TrimSpace(parts[0])] = strings.TrimSpace(parts[1])
		}
	}
	return result
}
