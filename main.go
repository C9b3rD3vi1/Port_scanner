package main

import (
	"bufio"
	"os"
	"time"
	"strings"
	"strconv"

	"fmt"

	"Port_scanner/port"


	//"github.com/elliotforbes/athena/port"
)



func main() {
	// Read target hostname from user input
	reader := bufio.NewReader(os.Stdin)
	fmt.Print("Enter target hostname (e.g., localhost or 192.168.1.1): ")
	hostname, _ := reader.ReadString('\n')
	hostname = strings.TrimSpace(hostname)


	// Read ports to scan from user input
	fmt.Print("Enter ports to scan (comma-separated, e.g., '80,443,3389') or press Enter to scan default ports: ")
	portsInput, _ := reader.ReadString('\n')
	portsInput = strings.TrimSpace(portsInput)

	var ports []int
	if portsInput != "" {
		portStrings := strings.Split(portsInput, ",")
		for _, portStr := range portStrings {
			port, err := strconv.Atoi(strings.TrimSpace(portStr))
			if err != nil {
				fmt.Printf("Invalid port number: %s\n", portStr)
				continue
			}
			ports = append(ports, port)
		}
	} else {
		// Default ports to scan if no input provided
		ports = []int{80, 443, 3389}
	}


	// Perform an initial scan on common ports
	fmt.Println("Starting Initial Scan on common ports (0-1024)...")
	results := port.InitialScan(hostname)
	fmt.Println(results)


	// Perform a wide scan on a larger range of ports
	fmt.Println("Starting Wide Scan on ports (0-49152)...")
	wideresults := port.WideScan(hostname)
	fmt.Println(wideresults)


	// Save results to files
	initialFileName := "initial_scan_results.txt"
	wideFileName := "wide_scan_results.txt"

	err := port.SaveResultsToFile(initialFileName, results)
	if err != nil {
		fmt.Printf("Error saving initial scan results: %v\n", err)
	} else {
		fmt.Printf("Initial Scan results saved to %s\n", initialFileName)
	}

	err = port.SaveResultsToFile(wideFileName, wideresults)
	if err != nil {
		fmt.Printf("Error saving wide scan results: %v\n", err)
	} else {
		fmt.Printf("Wide Scan results saved to %s\n", wideFileName)
	}




	// Perform ICMP port scan
	fmt.Println("Starting ICMP Port Scan on specified ports (e.g., 80, 443, 3389)...")
	timeout := time.Second * 5    // Replace with your desired timeout duration

	icmpResults := port.ScanICMPPorts(hostname, ports, timeout)
	fmt.Println("ICMP Port Scan Results:")
	for _, result := range icmpResults {
		fmt.Printf("Port: %s\tState: %s\tService: %s\n", result.Port, result.State, result.Service)
	}
	
// Save ICMP results to a file
	icmpFileName := "icmp_scan_results.txt"
	err = port.SaveResultsToFile(icmpFileName, icmpResults)
	if err != nil {
		fmt.Printf("Error saving ICMP scan results: %v\n", err)
	} else {
		fmt.Printf("ICMP Port Scan results saved to %s\n", icmpFileName)
	}
}