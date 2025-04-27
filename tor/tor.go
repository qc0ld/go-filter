package tor

import (
	"bufio"
	"fmt"
	"net"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

const (
	controlPort     = "127.0.0.1:9151"
	authPass        = "password"
	torTimeout      = 5 * time.Second
	expectedHash    = ""
	httpConcurrency = 5
	httpTimeout     = 10 * time.Second
)

var (
	nodeIDRegex    = regexp.MustCompile(`\$\b[0-9A-F]{40}\b`)
	ipv4Regex      = regexp.MustCompile(`\b(?:\d{1,3}\.){3}\d{1,3}\b`)
	circuitRegex   = regexp.MustCompile(`(\d+)\s+BUILT\s+(.*?)\s+(BUILD_FLAGS=.*)`)
	confluxIdRegex = regexp.MustCompile(`CONFLUX_ID=(\w+)`)
	responseTerm   = "250 "
)

type CircuitInfo struct {
	ID        int
	ExitIP    string
	ConfluxID string
	Created   time.Time
}

type TorControl struct {
	conn   net.Conn
	reader *bufio.Reader
	writer *bufio.Writer
}

func GetConfluxExitIPs() []string {
	tc, err := NewTorControl(controlPort)
	if err != nil {
		fmt.Println("Tor control error:", err)
		return nil
	}
	defer tc.Close()

	if _, err = tc.Authenticate(); err != nil {
		fmt.Println("Authentication error:", err)
		return nil
	}

	resp, err := tc.GetCircuitStatus()
	if err != nil {
		fmt.Println("Circuit status error:", err)
		return nil
	}

	return processCircuitResponse(tc, resp)
}

func NewTorControl(addr string) (*TorControl, error) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return nil, fmt.Errorf("connection failed: %w", err)
	}
	return &TorControl{
		conn:   conn,
		reader: bufio.NewReader(conn),
		writer: bufio.NewWriter(conn),
	}, nil
}

func (tc *TorControl) Authenticate() (string, error) {
	return tc.SendCommand("AUTHENTICATE \"" + authPass + "\"")
}

func (tc *TorControl) GetCircuitStatus() (string, error) {
	return tc.SendCommand("GETINFO circuit-status")
}

func (tc *TorControl) SendCommand(command string) (string, error) {
	tc.conn.SetDeadline(time.Now().Add(torTimeout))
	if _, err := tc.writer.WriteString(command + "\r\n"); err != nil {
		return "", err
	}
	if err := tc.writer.Flush(); err != nil {
		return "", err
	}
	return tc.readResponse()
}

func (tc *TorControl) readResponse() (string, error) {
	var response strings.Builder
	for {
		tc.conn.SetDeadline(time.Now().Add(torTimeout))
		line, err := tc.reader.ReadString('\n')
		if err != nil {
			return "", err
		}
		response.WriteString(line)
		if strings.HasPrefix(line, responseTerm) {
			break
		}
	}
	return response.String(), nil
}

func (tc *TorControl) Close() {
	tc.conn.Close()
}

func processCircuitResponse(tc *TorControl, response string) []string {
	var circuits []CircuitInfo
	lines := strings.Split(response, "\n")

	for _, line := range lines {
		if !strings.Contains(line, "CONFLUX_ID=") {
			continue
		}

		circuit := parseCircuitLine(tc, line)
		if circuit.ExitIP != "" {
			circuits = append(circuits, circuit)
		}
	}

	sort.Sort(sort.Reverse(ByCreated(circuits)))
	return uniqueIPs(circuits)
}

func parseCircuitLine(tc *TorControl, line string) CircuitInfo {
	matches := circuitRegex.FindStringSubmatch(line)
	if len(matches) < 4 {
		return CircuitInfo{ExitIP: "ERROR"}
	}

	id, _ := strconv.Atoi(matches[1])
	confluxID := confluxIdRegex.FindStringSubmatch(line)
	timeCreated := regexp.MustCompile(`TIME_CREATED=([\d\-T:.]+)`).FindStringSubmatch(line)

	if len(confluxID) < 2 || len(timeCreated) < 2 {
		return CircuitInfo{ExitIP: "ERROR"}
	}

	created, err := time.Parse("2006-01-02T15:04:05.999999", timeCreated[1])
	if err != nil {
		return CircuitInfo{ExitIP: "ERROR"}
	}

	circuit := CircuitInfo{
		ID:        id,
		ConfluxID: confluxID[1],
		Created:   created,
	}

	if nodes := nodeIDRegex.FindAllString(matches[2], -1); len(nodes) >= 3 {
		circuit.ExitIP = resolveExitNodeIP(tc, nodes[2])
	}

	return circuit
}

func resolveExitNodeIP(tc *TorControl, nodeID string) string {
	resp, err := tc.SendCommand("GETINFO ns/id/" + nodeID)
	if err != nil {
		return "ERROR"
	}
	if ip := ipv4Regex.FindString(resp); ip != "" {
		return ip
	}
	return "NOT_FOUND"
}

func uniqueIPs(circuits []CircuitInfo) []string {
	seen := make(map[string]struct{})
	var ips []string
	for _, c := range circuits {
		if c.ExitIP != "" && c.ExitIP != "ERROR" && c.ExitIP != "NOT_FOUND" {
			if _, exists := seen[c.ExitIP]; !exists {
				seen[c.ExitIP] = struct{}{}
				ips = append(ips, c.ExitIP)
			}
		}
	}
	return ips
}

type ByCreated []CircuitInfo

func (a ByCreated) Len() int           { return len(a) }
func (a ByCreated) Swap(i, j int)      { a[i], a[j] = a[j], a[i] }
func (a ByCreated) Less(i, j int) bool { return a[i].Created.Before(a[j].Created) }
