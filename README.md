# Port_scanner
Building security port scanner on go

The port package provides functionality for scanning TCP, UDP, and ICMP ports on a specified hostname or IP address. It supports scanning common ports, wide port ranges, and saving scan results to a file.

# Installation
To use this package, ensure you have Go installed. You can then install the package using:

    git clone https://github.com/Pelekingz/Port_scanner.git


# Functions

    InitialScan(hostname string) []ScanResult
Performs a scan of common UDP and TCP ports (0-1024) on the specified hostname.

    WideScan(hostname string) []ScanResult
Performs a scan of a wide range of UDP and TCP ports (0-49152) on the specified hostname.

    ScanPort(protocol, hostname string, port int) ScanResult
Scans a specified port using either UDP or TCP protocol on the specified hostname.

    ScanICMPPorts(hostname string, ports []int, timeout time.Duration) []ICMPScanResult
Scans ICMP ports on the specified hostname for a list of ports using ICMP protocol. Uses asynchronous goroutines for concurrent scanning.

    SaveResultsToFile(fileName string, results interface{}) error
Saves scan results to a specified file (fileName). Supports both []ScanResult and []ICMPScanResult types.

