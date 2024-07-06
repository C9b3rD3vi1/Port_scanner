package port

import (
	"fmt"
	"net"
	"bufio"
	"os"
	"strconv"
	"sync"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

type ScanResult struct {
	Port    string
	State   string
	Service string
}

// ICMP port scanner function structure for hostname
type ICMPScanResult struct {
	Port    string
	State   string
	Service string
}

// A commonPorts map is defined to store common port numbers and their associated services.

// Predefined list of common ports and services
var commonPorts = map[int]string{
	21:   "FTP",
	22:   "SSH",
	23:   "Telnet",
	25:   "SMTP",
	53:   "DNS",
	80:   "HTTP",
	110:  "POP3",
	143:  "IMAP",
	443:  "HTTPS",
	3389: "RDP",
	// Add more common ports and services as needed
}

// The getService function is used to look up the service name for a given port number.
func getService(port int) string {
	if service, exists := commonPorts[port]; exists {
		return service
	}
	return "Unknown"
}

// TCP port scanner function for localhost
func scanTCP(hostname string, port int) ScanResult {
	result := ScanResult{Port: strconv.Itoa(port) + "/tcp"}
	address := hostname + ":" + strconv.Itoa(port)
	conn, err := net.DialTimeout("tcp", address, 60*time.Second)

	if err != nil {
		result.State = "Closed"
		return result
	}

	defer conn.Close()
	result.State = "Open"
	result.Service = getService(port)
	return result
}

// UDP port scanner function for localhost
func scanUDP(hostname string, port int) ScanResult {
	result := ScanResult{Port: strconv.Itoa(port) + "/udp"}
	address := hostname + ":" + strconv.Itoa(port)
	conn, err := net.DialTimeout("udp", address, 60*time.Second)

	if err != nil {
		result.State = "Closed"
		return result
	}

	defer conn.Close()
	result.State = "Open"
	result.Service = getService(port)
	return result
}

// Port scanner function
func ScanPort(protocol, hostname string, port int) ScanResult {
	if protocol == "udp" {
		return scanUDP(hostname, port)
	} else if protocol == "tcp" {
		return scanTCP(hostname, port)
	}

	result := ScanResult{Port: strconv.Itoa(port) + "/" + protocol}
	result.State = "Unknown protocol"
	return result
}

// Initial port scanner function for localhost
func InitialScan(hostname string) []ScanResult {

	var results []ScanResult

	for i := 0; i <= 1024; i++ {
		results = append(results, ScanPort("udp", hostname, i))
	}

	for i := 0; i <= 1024; i++ {
		results = append(results, ScanPort("tcp", hostname, i))
	}

	return results
}

// Wide port scanner function for localhost
func WideScan(hostname string) []ScanResult {
	var results []ScanResult

	for i := 0; i <= 49152; i++ {
		results = append(results, ScanPort("udp", hostname, i))
	}

	for i := 0; i <= 49152; i++ {
		results = append(results, ScanPort("tcp", hostname, i))
	}

	return results
}

// ScanICMPWithFastPing performs an ICMP port scan on the specified IP address using go-fastping library.
// ScanICMPPorts performs an ICMP port scan on the specified IP address and ports.
func ScanICMPPorts(hostname string, ports []int, timeout time.Duration) []ICMPScanResult {
	var results []ICMPScanResult
	var wg sync.WaitGroup

	// Create a new ICMP connection
	c, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		fmt.Printf("Error listening for ICMP packets: %v\n", err)
		return results
	}
	defer c.Close()

	dstIP := net.ParseIP(hostname)
	if dstIP == nil {
		fmt.Printf("Invalid hostname address: %s\n", hostname)
		return results
	}

	echoRequest := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{
			ID: os.Getpid() & 0xffff, Seq: 1,
			Data: []byte("HELLO-RPC"),
		},
	}

	echoRequestBytes, err := echoRequest.Marshal(nil)
	if err != nil {
		fmt.Printf("Error marshaling ICMP message: %v\n", err)
		return results
	}

	received := make(chan ICMPScanResult, 1)
	defer close(received)

	go func() {
		for {
			select {
			case <-time.After(timeout):
				return
			default:
				buf := make([]byte, 1500)
				err := c.SetReadDeadline(time.Now().Add(time.Millisecond * 100))
				if err != nil {
					fmt.Printf("Error setting read deadline: %v\n", err)
					return
				}
				n, _, err := c.ReadFrom(buf)
				if err != nil {
					continue
				}
				// Process ICMP response here
				rm, err := icmp.ParseMessage(1, buf[:n])
				if err != nil {
					fmt.Printf("Error parsing ICMP message: %v\n", err)
					return
				}
				switch rm.Type {
				case ipv4.ICMPTypeEchoReply:
					received <- ICMPScanResult{Port: "ICMP", State: "Open"}
				}
			}
		}
	}()

	for _, port := range ports {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()

			address := fmt.Sprintf("%s:%d", hostname, port)
			dstAddr, err := net.ResolveIPAddr("ip4", address)
			if err != nil {
				fmt.Printf("Error resolving hostname address: %v\n", err)
				return
			}

			_, err = c.WriteTo(echoRequestBytes, dstAddr)
			if err != nil {
				return
			}

			select {
			case result := <-received:
				result.Port = strconv.Itoa(port) + "/icmp"
				result.Service = getService(port)
				results = append(results, result)
			case <-time.After(timeout):
				results = append(results, ICMPScanResult{Port: strconv.Itoa(port) + "/icmp", State: "Closed"})
			}
		}(port)
	}

	wg.Wait()

	return results
}


// SaveResultsToFile saves the given scan results to a file.
func SaveResultsToFile(fileName string, results interface{}) error {
	file, err := os.Create(fileName)
	if err != nil {
		return err
	}
	defer file.Close()

	writer := bufio.NewWriter(file)
	switch v := results.(type) {
	case []ScanResult:
		for _, result := range v {
			_, err := fmt.Fprintf(writer, "Port: %s\tState: %s\tService: %s\n", result.Port, result.State, result.Service)
			if err != nil {
				return err
			}
		}
	case []ICMPScanResult:
		for _, result := range v {
			_, err := fmt.Fprintf(writer, "Port: %s\tState: %s\tService: %s\n", result.Port, result.State, result.Service)
			if err != nil {
				return err
			}
		}
	default:
		return fmt.Errorf("unsupported type: %T", results)
	}

	return writer.Flush()
}