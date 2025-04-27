package main

import (
	"bytes"
	"context"
	"fmt"
	"log"
	"net"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"

	"gofilter/database"
	"gofilter/tor"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/vishvananda/netlink"
	"golang.org/x/sys/unix"
)

const (
	shutdownTimeout  = 2 * time.Second
	dbTimeout        = 1 * time.Second
	torCheckInterval = 30 * time.Second
	torControlPort   = "127.0.0.1:9151"
	snapshotLength   = 1600
)

var (
	logger = log.New(os.Stdout, "[IP-FILTER] ", log.Ltime)
)

type App struct {
	ctx            context.Context
	cancel         context.CancelFunc
	wg             sync.WaitGroup
	handle         *pcap.Handle
	iface          string
	processedIPs   sync.Map
	shutdownOnce   sync.Once
	shutdownChan   chan struct{}
	routeCache     []netlink.Route
	routeCacheMux  sync.Mutex
	isTorActive    bool
	torMux         sync.Mutex
	hostMap        map[string]string
	hostMapMux     sync.Mutex
	torCheckTicker *time.Ticker
	torCheckQuit   chan struct{}
	torCheckMux    sync.Mutex
}

func NewApp(iface string) *App {
	ctx, cancel := context.WithCancel(context.Background())
	return &App{
		ctx:          ctx,
		cancel:       cancel,
		iface:        iface,
		shutdownChan: make(chan struct{}),
		hostMap:      make(map[string]string),
	}
}

func main() {
	app := NewApp("eth0")
	defer app.Shutdown()

	if err := database.InitializeDatabase(); err != nil {
		logger.Fatalf("Database init failed: %v", err)
	}

	if err := app.Initialize(); err != nil {
		logger.Fatalf("Initialization error: %v", err)
	}

	app.Run()
	<-app.shutdownChan
}

func (a *App) Initialize() error {
	if err := database.ConnectAndCheck(); err != nil {
		return fmt.Errorf("database: %w", err)
	}

	handle, err := pcap.OpenLive(a.iface, snapshotLength, true, pcap.BlockForever)
	if err != nil {
		return fmt.Errorf("pcap init: %w", err)
	}
	a.handle = handle

	return nil
}

func (a *App) Run() {
	a.wg.Add(1)
	go a.packetWorker()
	a.wg.Add(1)
	go a.torChecker()
	a.wg.Add(1)
	go a.signalHandler()

	logger.Println("Application started")
}

func (a *App) packetWorker() {
	defer a.wg.Done()
	source := gopacket.NewPacketSource(a.handle, a.handle.LinkType())
	source.DecodeOptions = gopacket.DecodeOptions{Lazy: true, NoCopy: true}

	for {
		select {
		case <-a.ctx.Done():
			return
		case packet, ok := <-source.Packets():
			if !ok {
				return
			}
			a.processPacket(packet)
		}
	}
}

func (a *App) processPacket(packet gopacket.Packet) {
	ipLayer := packet.Layer(layers.LayerTypeIPv4)
	if ipLayer == nil {
		return
	}

	ipv4, _ := ipLayer.(*layers.IPv4)
	dstIP := ipv4.DstIP.String()

	if _, loaded := a.processedIPs.LoadOrStore(dstIP, struct{}{}); !loaded {
		a.checkIP(dstIP)
	}

	a.torMux.Lock()
	torActive := a.isTorActive
	a.torMux.Unlock()

	if torActive {
		a.analyzeHTTPS(packet, ipv4)
		a.scheduleTorCheck()
	}
}

func (a *App) scheduleTorCheck() {
	a.torCheckMux.Lock()
	defer a.torCheckMux.Unlock()

	if a.torCheckTicker == nil {
		a.torCheckTicker = time.NewTicker(30 * time.Second)
		a.torCheckQuit = make(chan struct{})

		go func() {
			defer func() {
				a.torCheckMux.Lock()
				a.torCheckTicker.Stop()
				a.torCheckTicker = nil
				a.torCheckMux.Unlock()
			}()

			for {
				select {
				case <-a.torCheckTicker.C:
					exitIPs := tor.GetConfluxExitIPs()
					for _, ip := range exitIPs {
						logger.Printf("Checking IP address in Tor circuit: %s", ip)

						blocked, err := database.TorIsIPBlocked(ip)
						if err != nil {
							logger.Printf("IP check error: %v", err)
							continue
						}
						if blocked {
							logger.Printf("Blocked Tor node detected: %s", ip)
							a.stopTorBrowser()
							return
						}
					}
				case <-a.torCheckQuit:
					return
				}
			}
		}()
	}
}

func (a *App) stopTorBrowser() {
	a.torMux.Lock()
	defer a.torMux.Unlock()

	if a.isTorActive {
		// Реализация остановки Tor процесса
		// Пример для Unix-систем:
		// if pid != 0 {
		//     syscall.Kill(pid, syscall.SIGTERM)
		// }
		a.isTorActive = false
		logger.Println("Tor browser terminated due to blocked node")

		// Остановка проверки
		if a.torCheckQuit != nil {
			close(a.torCheckQuit)
		}
	}
}

func (a *App) checkIP(ip string) {
	isBlocked, err := database.IsIPBlocked(ip)
	if err != nil {
		logger.Printf("DB error for %s: %v", ip, err)
		return
	}

	if isBlocked {
		a.blockIP(ip)
	}
}

func (a *App) blockIP(ip string) {
	a.routeCacheMux.Lock()
	defer a.routeCacheMux.Unlock()

	_, dstNet, err := net.ParseCIDR(ip + "/32")
	if err != nil {
		logger.Printf("Invalid IP %s: %v", ip, err)
		return
	}

	route := &netlink.Route{
		Dst:      dstNet,
		Type:     unix.RTN_BLACKHOLE,
		Table:    unix.RT_TABLE_MAIN,
		Protocol: unix.RTPROT_STATIC,
	}

	if err := netlink.RouteAdd(route); err != nil {
		logger.Printf("Block failed %s: %v", ip, err)
		return
	}

	a.routeCache = append(a.routeCache, *route)
	logger.Printf("Blocked IP: %s", ip)
}

func (a *App) analyzeHTTPS(packet gopacket.Packet, ipv4 *layers.IPv4) {
	tcpLayer := packet.Layer(layers.LayerTypeTCP)
	if tcpLayer == nil {
		return
	}

	tcp, _ := tcpLayer.(*layers.TCP)
	payload := tcp.Payload
	if len(payload) == 0 {
		return
	}

	switch {
	case isHTTPRequest(payload):
		a.handleHTTPRequest(ipv4, tcp, payload)
	case isHTTPResponse(payload):
		a.handleHTTPResponse(ipv4, tcp, payload)
	}
}

func (a *App) handleHTTPRequest(ipv4 *layers.IPv4, tcp *layers.TCP, payload []byte) {
	host := extractHost(payload)
	if host == "" {
		return
	}

	key := fmt.Sprintf("%s:%d", ipv4.DstIP, tcp.DstPort)
	a.hostMapMux.Lock()
	a.hostMap[key] = host
	a.hostMapMux.Unlock()

	logger.Printf("HTTPS Request: %s => %s", key, host)
}

func (a *App) handleHTTPResponse(ipv4 *layers.IPv4, tcp *layers.TCP, payload []byte) {
	location := extractLocation(payload)
	if location == "" {
		return
	}

	key := fmt.Sprintf("%s:%d", ipv4.SrcIP, tcp.SrcPort)
	a.hostMapMux.Lock()
	expectedHost, exists := a.hostMap[key]
	a.hostMapMux.Unlock()

	if exists && !isSameDomain(expectedHost, location) {
		logger.Printf("Phishing Alert! Expected: %s, Got: %s", expectedHost, location)
		a.blockIP(ipv4.SrcIP.String())
	}
}

func (a *App) torChecker() {
	defer a.wg.Done()
	ticker := time.NewTicker(torCheckInterval)
	defer ticker.Stop()

	for {
		select {
		case <-a.ctx.Done():
			return
		case <-ticker.C:
			if a.checkTorConnection() {
				a.updateTorStatus(true)
			} else {
				a.updateTorStatus(false)
			}
		}
	}
}

func (a *App) checkTorConnection() bool {
	conn, err := net.DialTimeout("tcp", torControlPort, 1*time.Second)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

func (a *App) updateTorStatus(active bool) {
	a.torMux.Lock()
	defer a.torMux.Unlock()

	if a.isTorActive != active {
		a.isTorActive = active
		status := "active"
		if !active {
			status = "inactive"
		}
		logger.Printf("Tor status changed: %s", status)
	}
}

func (a *App) signalHandler() {
	defer a.wg.Done()
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	select {
	case <-sigChan:
		logger.Println("Shutting down...")
		a.emergencyShutdown()
	case <-a.ctx.Done():
	}
}

func (a *App) emergencyShutdown() {
	a.shutdownOnce.Do(func() {
		a.cancel()
		go a.forceShutdown()
		a.cleanup()
		close(a.shutdownChan)
	})
}

func (a *App) forceShutdown() {
	time.Sleep(shutdownTimeout)
	logger.Println("Force shutdown!")
	os.Exit(1)
}

func (a *App) cleanup() {
	ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
	defer cancel()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		a.cleanupRoutes(ctx)
	}()

	wg.Add(1)
	go func() {
		defer wg.Done()
		a.cleanupPacketCapture()
	}()

	wg.Wait()
}

func (a *App) cleanupRoutes(ctx context.Context) {
	a.routeCacheMux.Lock()
	defer a.routeCacheMux.Unlock()

	logger.Println("Clearing routes...")
	var wg sync.WaitGroup

	for _, route := range a.routeCache {
		wg.Add(1)
		go func(r netlink.Route) {
			defer wg.Done()
			if err := netlink.RouteDel(&r); err != nil {
				logger.Printf("Route delete failed: %v", err)
			}
		}(route)
	}

	done := make(chan struct{})
	go func() {
		wg.Wait()
		close(done)
	}()

	select {
	case <-done:
	case <-ctx.Done():
	}
}

func (a *App) cleanupPacketCapture() {
	if a.handle != nil {
		a.handle.Close()
	}
}

func (a *App) Shutdown() {
	a.emergencyShutdown()
	a.wg.Wait()
}

func isHTTPRequest(payload []byte) bool {
	return bytes.HasPrefix(payload, []byte("GET ")) ||
		bytes.HasPrefix(payload, []byte("POST ")) ||
		bytes.HasPrefix(payload, []byte("PUT ")) ||
		bytes.HasPrefix(payload, []byte("HEAD ")) ||
		bytes.HasPrefix(payload, []byte("DELETE "))
}

func extractHost(payload []byte) string {
	for _, line := range bytes.Split(payload, []byte("\r\n")) {
		if bytes.HasPrefix(line, []byte("Host: ")) {
			return string(bytes.TrimSpace(line[5:]))
		}
	}
	return ""
}

func isHTTPResponse(payload []byte) bool {
	return bytes.HasPrefix(payload, []byte("HTTP/"))
}

func extractLocation(payload []byte) string {
	for _, line := range bytes.Split(payload, []byte("\r\n")) {
		if bytes.HasPrefix(line, []byte("Location: ")) {
			return string(bytes.TrimSpace(line[10:]))
		}
	}
	return ""
}

func isSameDomain(a, b string) bool {
	normalize := func(s string) string {
		s = strings.ToLower(s)
		s = strings.TrimPrefix(s, "http://")
		s = strings.TrimPrefix(s, "https://")
		s = strings.Split(s, "/")[0]
		return s
	}
	return normalize(a) == normalize(b)
}
