package radius

import (
	"context"
	"fmt"
	"log"
	"net"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/mwittenburg/unifi-radius-server/pkg/database"
	"github.com/mwittenburg/unifi-radius-server/pkg/eventbus"
	"github.com/mwittenburg/unifi-radius-server/pkg/models"
	"github.com/mwittenburg/unifi-radius-server/pkg/utils"
	"golang.org/x/crypto/bcrypt"
)

var dummyBcryptHash string

func init() {
	h, err := bcrypt.GenerateFromPassword([]byte("dummy_password_timing_defense"), bcrypt.DefaultCost)
	if err == nil {
		dummyBcryptHash = string(h)
	}
}

type udpPacket struct {
	data       []byte
	remoteAddr *net.UDPAddr
}

// Server is the high-performance multi-threaded UDP RADIUS server engine.
type Server struct {
	db          *database.DB
	bus         *eventbus.Bus
	cache       *FastCache
	batchWriter *BatchWriter
	port        int
	conn        *net.UDPConn
	packetQueue chan udpPacket
	bufPool     sync.Pool
	numWorkers  int
	stopChan    chan struct{}
	wg          sync.WaitGroup
	mu          sync.RWMutex
	listening   bool
	debugMode   bool
}

// NewServer initializes a high-concurrency RADIUS server instance.
func NewServer(db *database.DB, bus *eventbus.Bus, port int) *Server {
	if port <= 0 {
		port = 1812
	}
	if bus == nil {
		bus = eventbus.DefaultBus
	}

	numWorkers := runtime.NumCPU() * 4
	if numWorkers < 16 {
		numWorkers = 16
	} else if numWorkers > 64 {
		numWorkers = 64
	}

	cache := NewFastCache(db)
	bw := NewBatchWriter(db)

	return &Server{
		db:          db,
		bus:         bus,
		cache:       cache,
		batchWriter: bw,
		port:        port,
		packetQueue: make(chan udpPacket, 8192),
		bufPool: sync.Pool{
			New: func() interface{} {
				b := make([]byte, 4096)
				return &b
			},
		},
		numWorkers: numWorkers,
		stopChan:   make(chan struct{}),
	}
}

// ReloadCache instructs the in-memory cache to refresh from SQLite.
func (s *Server) ReloadCache() error {
	return s.cache.Reload()
}

// SetDebugMode enables or disables real-time raw packet debugging and hex dumps.
func (s *Server) SetDebugMode(enabled bool) {
	s.mu.Lock()
	s.debugMode = enabled
	s.mu.Unlock()
}

// IsDebugMode returns whether raw packet debugging is currently active.
func (s *Server) IsDebugMode() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.debugMode
}

// Start opens the UDP listener with enlarged kernel buffers and spawns the worker pool.
// If the port is currently in use (e.g. by UniFi's built-in FreeRADIUS daemon),
// it keeps the server running and automatically retries binding in the background
// so the Web UI remains available for migration or configuration.
func (s *Server) Start(ctx context.Context) error {
	// Start asynchronous batch database writer
	s.batchWriter.Start(ctx)

	go func() {
		<-ctx.Done()
		s.Stop()
	}()

	// Spawn concurrent worker pool once
	for i := 0; i < s.numWorkers; i++ {
		s.wg.Add(1)
		go s.worker(i)
	}

	// Try initial listen
	addr := net.UDPAddr{
		Port: s.port,
		IP:   net.ParseIP("0.0.0.0"),
	}

	conn, err := net.ListenUDP("udp", &addr)
	if err == nil {
		s.setupAndServe(conn)
		return nil
	}

	// Port is occupied (e.g. built-in FreeRADIUS) or network error
	log.Printf("[WARN] [RADIUS] Port %d ist belegt (%v). Webinterface bleibt aktiv. Starte automatische Wiederholungsversuche alle 3 Sekunden...", s.port, err)
	s.bus.PublishLog(eventbus.LogEvent{
		Timestamp: time.Now().Format("15:04:05"),
		Level:     eventbus.LogLevelWarn,
		Source:    "RADIUS",
		Message:   fmt.Sprintf("UDP-Port %d ist belegt (%v, vermutlich UniFi FreeRADIUS). Bitte unter 'Einstellungen -> UniFi Migration' migrieren. Wiederhole Bind-Versuche...", s.port, err),
	})

	// Retry loop in background
	go s.listenLoop(ctx)

	return nil
}

func (s *Server) setupAndServe(conn *net.UDPConn) {
	s.mu.Lock()
	s.conn = conn
	s.listening = true
	s.mu.Unlock()

	// Maximize socket kernel buffers to prevent packet drops during heavy bursts (e.g. switch reboot storm)
	_ = s.conn.SetReadBuffer(4 * 1024 * 1024)  // 4 MB socket read buffer
	_ = s.conn.SetWriteBuffer(4 * 1024 * 1024) // 4 MB socket write buffer

	log.Printf("[RADIUS] High-Performance Server listening on UDP :%d (%d worker threads, in-memory cache active)", s.port, s.numWorkers)
	s.bus.PublishLog(eventbus.LogEvent{
		Timestamp: time.Now().Format("15:04:05"),
		Level:     eventbus.LogLevelInfo,
		Source:    "RADIUS",
		Message:   fmt.Sprintf("RADIUS service listening on UDP port %d (%d worker threads)", s.port, s.numWorkers),
	})

	s.wg.Add(1)
	go s.serve()
}

func (s *Server) listenLoop(ctx context.Context) {
	ticker := time.NewTicker(3 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ctx.Done():
			return
		case <-s.stopChan:
			return
		case <-ticker.C:
			s.mu.RLock()
			alreadyListening := s.listening
			port := s.port
			s.mu.RUnlock()

			if alreadyListening {
				return
			}

			addr := net.UDPAddr{
				Port: port,
				IP:   net.ParseIP("0.0.0.0"),
			}
			conn, err := net.ListenUDP("udp", &addr)
			if err == nil {
				log.Printf("[RADIUS] UDP-Port %d erfolgreich gebunden!", port)
				s.setupAndServe(conn)
				return
			}
		}
	}
}

// IsListening returns true if the UDP socket is actively bound and receiving packets.
func (s *Server) IsListening() bool {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.listening
}

// Port returns the configured UDP port for the RADIUS server.
func (s *Server) Port() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.port
}

// Stop cleanly terminates the UDP listener, drains queues, and flushes database batches.
func (s *Server) Stop() {
	select {
	case <-s.stopChan:
		return
	default:
		close(s.stopChan)
	}
	s.mu.Lock()
	s.listening = false
	if s.conn != nil {
		s.conn.Close()
	}
	s.mu.Unlock()
	s.batchWriter.Stop()
	s.wg.Wait()
	log.Println("[RADIUS] Server stopped cleanly.")
}

func (s *Server) serve() {
	defer s.wg.Done()

	for {
		bufPtr := s.bufPool.Get().(*[]byte)
		buf := *bufPtr

		n, remoteAddr, err := s.conn.ReadFromUDP(buf)
		if err != nil {
			s.bufPool.Put(bufPtr)
			select {
			case <-s.stopChan:
				return
			default:
				log.Printf("[RADIUS] Error reading UDP socket: %v", err)
				continue
			}
		}

		packetCopy := make([]byte, n)
		copy(packetCopy, buf[:n])
		s.bufPool.Put(bufPtr)

		item := udpPacket{data: packetCopy, remoteAddr: remoteAddr}

		select {
		case s.packetQueue <- item:
		default:
			// High-load overflow: spawn temporary worker to avoid dropping packet
			go s.handlePacket(item.data, item.remoteAddr)
		}
	}
}

func (s *Server) worker(id int) {
	defer s.wg.Done()

	for {
		select {
		case <-s.stopChan:
			return
		case item := <-s.packetQueue:
			s.handlePacket(item.data, item.remoteAddr)
		}
	}
}

func (s *Server) handlePacket(data []byte, remoteAddr *net.UDPAddr) {
	start := time.Now()
	req, err := ParsePacket(data)
	if err != nil {
		log.Printf("[RADIUS] Malformed packet from %s: %v", remoteAddr, err)
		return
	}

	if req.Code != CodeAccessRequest {
		return // Only Access-Requests handled on auth port
	}

	// 1. Resolve Settings & NAS Client from Fast RAM Cache (zero DB query)
	settings := s.cache.GetSettings()
	debugActive := s.IsDebugMode() || settings.RadiusDebugMode
	rawReqDebug := req.FormatDebug(data)

	if debugActive {
		s.bus.PublishLog(eventbus.LogEvent{
			Timestamp: time.Now().Format("15:04:05"),
			Level:     eventbus.LogLevelDebug,
			Source:    "RADIUS-RAW",
			Message:   fmt.Sprintf("<<< RECV %s from %s (ID:%d, len:%d)\n%s", req.CodeName(), remoteAddr, req.Identifier, len(data), rawReqDebug),
		})
	}

	remoteIP := remoteAddr.IP.String()

	nas, found := s.cache.LookupNAS(remoteIP)
	sharedSecret := settings.GlobalSharedSecret
	nasName := "UniFi Device"

	if found && nas != nil {
		if nas.SharedSecret != "" {
			sharedSecret = nas.SharedSecret
		}
		if nas.Name != "" {
			nasName = nas.Name
		}
	} else if sharedSecret == "" {
		log.Printf("[RADIUS] Rejected request from %s: unknown NAS and no global secret configured", remoteIP)
		return
	}

	secretBytes := []byte(sharedSecret)

	// Validate Message-Authenticator if present
	if !ValidateMessageAuthenticator(data, secretBytes) {
		log.Printf("[RADIUS] Message-Authenticator signature mismatch from NAS %s", remoteIP)
		return
	}

	// 2. Extract Packet Attributes
	rawUserName := req.GetString(AttrUserName)
	callingStationID := req.GetString(AttrCallingStationID)
	nasPort := req.GetString(AttrNASPort)
	if nasPort == "" {
		nasPort = strconv.Itoa(int(binaryToUint(req.GetAttribute(AttrNASPort))))
	}

	// Determine client identifier (MAB vs User)
	var macCandidate string
	if utils.IsValidMAC(callingStationID) {
		macCandidate = callingStationID
	} else if utils.IsValidMAC(rawUserName) {
		macCandidate = rawUserName
	}

	var authType models.AuthType
	var status string
	var assignedVLAN *int
	var logReason string
	var enrichedName, enrichedVendor string
	var clientMAC, username string

	var respPacket *Packet

	if macCandidate != "" {
		// --- MAB (MAC Authentication Bypass) Processing ---
		authType = models.AuthTypeMAB
		normMAC, _ := utils.NormalizeMAC(macCandidate)
		clientMAC = normMAC

		// Microsecond in-memory lookup
		client, clientFound := s.cache.LookupClientByMAC(normMAC)
		if clientFound && client != nil {
			enrichedName = client.UniFiName
			enrichedVendor = client.UniFiVendor

			switch client.Status {
			case models.ClientStatusActive:
				vlan := client.EffectiveVLAN(settings.DefaultAllowVLAN)
				assignedVLAN = &vlan
				status = "ACCEPT"
				logReason = fmt.Sprintf("Authorized MAB client -> VLAN %d", vlan)

				respPacket = req.CreateResponse(CodeAccessAccept)
				respPacket.AddDynamicVLAN(vlan)

				// Async non-blocking timestamp update
				s.batchWriter.EnqueueLastSeen(client.ID, time.Now())

			case models.ClientStatusDisabled:
				status = "REJECT"
				logReason = "Client is disabled by administrator"
				respPacket = req.CreateResponse(CodeAccessReject)

			case models.ClientStatusPending:
				if settings.UnknownMABPolicy == models.PolicyAutoAcceptUnknown {
					vlan := client.EffectiveVLAN(settings.DefaultAllowVLAN)
					assignedVLAN = &vlan
					status = "ACCEPT"
					logReason = fmt.Sprintf("Pending client auto-accepted -> VLAN %d", vlan)
					respPacket = req.CreateResponse(CodeAccessAccept)
					respPacket.AddDynamicVLAN(vlan)
				} else {
					status = "REJECT"
					logReason = "Client is in pending approval queue"
					respPacket = req.CreateResponse(CodeAccessReject)
				}
				s.batchWriter.EnqueueLastSeen(client.ID, time.Now())
			}
		} else {
			// Unknown MAC address
			switch settings.UnknownMABPolicy {
			case models.PolicyAutoAcceptUnknown:
				vlan := settings.DefaultAllowVLAN
				assignedVLAN = &vlan
				status = "ACCEPT"
				logReason = fmt.Sprintf("Unknown MAC auto-accepted into Default VLAN %d", vlan)

				newPending := &models.Client{
					MACAddress:  normMAC,
					AuthType:    models.AuthTypeMAB,
					VLANID:      &vlan,
					Status:      models.ClientStatusPending,
					Description: "Auto-discovered MAB device",
				}
				s.cache.OptimisticInsertMAC(newPending)
				s.batchWriter.EnqueuePendingClient(newPending)

				respPacket = req.CreateResponse(CodeAccessAccept)
				respPacket.AddDynamicVLAN(vlan)

			case models.PolicyRejectAndLog:
				vlan := settings.DefaultAllowVLAN
				status = "REJECT"
				logReason = "Unknown MAC - recorded in Pending queue for approval"

				newPending := &models.Client{
					MACAddress:  normMAC,
					AuthType:    models.AuthTypeMAB,
					VLANID:      &vlan,
					Status:      models.ClientStatusPending,
					Description: "Auto-discovered MAB device",
				}
				s.cache.OptimisticInsertMAC(newPending)
				s.batchWriter.EnqueuePendingClient(newPending)

				respPacket = req.CreateResponse(CodeAccessReject)

			case models.PolicyStrictReject:
				status = "REJECT"
				logReason = "Unknown MAC rejected by strict policy"
				respPacket = req.CreateResponse(CodeAccessReject)
			}
		}
	} else if rawUserName != "" {
		// --- 802.1X / PAP User Authentication ---
		username = strings.TrimSpace(rawUserName)
		authType = models.AuthTypePAP

		encPass := req.GetAttribute(AttrUserPassword)
		plainPass, decryptErr := DecryptUserPassword(encPass, req.Authenticator, secretBytes)

		client, userFound := s.cache.LookupClientByUser(username)
		if !userFound || client == nil {
			// Constant-time mitigation against user enumeration
			if decryptErr == nil && dummyBcryptHash != "" {
				_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(plainPass))
			}
			status = "REJECT"
			logReason = fmt.Sprintf("User '%s' not found", username)
			respPacket = req.CreateResponse(CodeAccessReject)
		} else if client.Status == models.ClientStatusDisabled {
			if decryptErr == nil && dummyBcryptHash != "" {
				_ = bcrypt.CompareHashAndPassword([]byte(dummyBcryptHash), []byte(plainPass))
			}
			status = "REJECT"
			logReason = fmt.Sprintf("User '%s' is disabled", username)
			respPacket = req.CreateResponse(CodeAccessReject)
		} else {
			// Validate password
			passValid := false
			if decryptErr == nil {
				if client.PasswordHash != "" {
					if strings.HasPrefix(client.PasswordHash, "$2a$") || strings.HasPrefix(client.PasswordHash, "$2b$") || strings.HasPrefix(client.PasswordHash, "$2y$") {
						passValid = bcrypt.CompareHashAndPassword([]byte(client.PasswordHash), []byte(plainPass)) == nil
					} else {
						passValid = client.PasswordHash == plainPass
					}
				}
			}

			if passValid {
				vlan := client.EffectiveVLAN(settings.DefaultAllowVLAN)
				assignedVLAN = &vlan
				status = "ACCEPT"
				logReason = fmt.Sprintf("User '%s' authenticated -> VLAN %d", username, vlan)

				respPacket = req.CreateResponse(CodeAccessAccept)
				respPacket.AddDynamicVLAN(vlan)
				s.batchWriter.EnqueueLastSeen(client.ID, time.Now())
			} else {
				status = "REJECT"
				logReason = fmt.Sprintf("Invalid credentials for user '%s'", username)
				respPacket = req.CreateResponse(CodeAccessReject)
			}
		}
	} else {
		status = "REJECT"
		logReason = "Empty username / calling-station-id"
		respPacket = req.CreateResponse(CodeAccessReject)
	}

	latency := float64(time.Since(start).Microseconds()) / 1000.0

	// 3. Send Response IMMEDIATELY to Switch/AP (Fast Path)
	respBytes, err := respPacket.Encode(secretBytes)
	rawRespDebug := ""
	if err == nil {
		rawRespDebug = respPacket.FormatDebug(respBytes)
		if debugActive {
			s.bus.PublishLog(eventbus.LogEvent{
				Timestamp: time.Now().Format("15:04:05"),
				Level:     eventbus.LogLevelDebug,
				Source:    "RADIUS-RAW",
				Message:   fmt.Sprintf(">>> SENT %s to %s (ID:%d, len:%d)\n%s", respPacket.CodeName(), remoteAddr, respPacket.Identifier, len(respBytes), rawRespDebug),
			})
		}
		_, _ = s.conn.WriteToUDP(respBytes, remoteAddr)
	} else {
		log.Printf("[RADIUS] Failed to encode response: %v", err)
	}

	// 4. Asynchronous Non-Blocking Logging & WebSocket Broadcast (Slow Path)
	authLog := models.AuthLog{
		Timestamp:      time.Now().UTC(),
		ClientMAC:      clientMAC,
		Username:       username,
		NASIP:          remoteIP,
		NASPort:        nasPort,
		AuthType:       authType,
		Status:         status,
		VLANID:         assignedVLAN,
		Reason:         logReason,
		LatencyMS:      latency,
		EnrichedName:   enrichedName,
		EnrichedVendor: enrichedVendor,
		RawRequest:     rawReqDebug,
		RawResponse:    rawRespDebug,
	}

	// Enqueue to batch writer (non-blocking, flushed in bulk)
	s.batchWriter.EnqueueLog(&authLog)

	// Broadcast live feed over WebSocket bus
	s.bus.PublishAuth(authLog)

	// Stream log line to console
	level := eventbus.LogLevelInfo
	if status == "REJECT" {
		level = eventbus.LogLevelWarn
	}
	s.bus.PublishLog(eventbus.LogEvent{
		Timestamp: time.Now().Format("15:04:05"),
		Level:     level,
		Source:    "RADIUS",
		Message:   fmt.Sprintf("[%s] %s (%s) from %s:%s -> %s (%.2fms)", status, firstNonEmpty(clientMAC, username), nasName, remoteIP, nasPort, logReason, latency),
	})
}

func binaryToUint(b []byte) uint32 {
	if len(b) == 0 {
		return 0
	}
	if len(b) >= 4 {
		return (uint32(b[0]) << 24) | (uint32(b[1]) << 16) | (uint32(b[2]) << 8) | uint32(b[3])
	}
	if len(b) == 2 {
		return (uint32(b[0]) << 8) | uint32(b[1])
	}
	return uint32(b[0])
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}
