#!/usr/bin/env python3
"""
Advanced Professional Port Scanner & Network Reconnaissance Tool
Enhanced version with comprehensive OS detection and service enumeration
Author: Security Research Team
Version: 3.0 Professional Edition
"""

import socket
import threading
import argparse
import sys
import time
import subprocess
import json
import ipaddress
import random
import struct
import re
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed
from collections import defaultdict
import platform

class TerminalColors:
    """Enhanced terminal color management"""
    HEADER = '\033[95m'
    BLUE = '\033[94m'
    CYAN = '\033[96m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    RED = '\033[91m'
    MAGENTA = '\033[95m'
    WHITE = '\033[97m'
    BOLD = '\033[1m'
    UNDERLINE = '\033[4m'
    BLINK = '\033[5m'
    REVERSE = '\033[7m'
    END = '\033[0m'
    
    @staticmethod
    def colorize(text, color):
        return f"{color}{text}{TerminalColors.END}"

class ServiceDatabase:
    """Comprehensive service and port database"""
    
    COMMON_PORTS = {
        # Network Services
        21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
        67: 'DHCP', 68: 'DHCP', 69: 'TFTP', 80: 'HTTP', 110: 'POP3',
        119: 'NNTP', 123: 'NTP', 135: 'RPC', 137: 'NetBIOS', 138: 'NetBIOS',
        139: 'NetBIOS', 143: 'IMAP', 161: 'SNMP', 162: 'SNMP', 389: 'LDAP',
        443: 'HTTPS', 445: 'SMB', 465: 'SMTPS', 514: 'Syslog', 587: 'SMTP',
        636: 'LDAPS', 993: 'IMAPS', 995: 'POP3S',
        
        # Database Services
        1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 5432: 'PostgreSQL',
        6379: 'Redis', 27017: 'MongoDB', 5984: 'CouchDB', 9200: 'Elasticsearch',
        
        # Web Services
        8080: 'HTTP-Alt', 8443: 'HTTPS-Alt', 8000: 'HTTP-Alt', 8008: 'HTTP-Alt',
        8888: 'HTTP-Alt', 9000: 'HTTP-Alt', 3000: 'Node.js', 4000: 'HTTP-Alt',
        
        # Remote Access
        3389: 'RDP', 5900: 'VNC', 5800: 'VNC-Web', 22: 'SSH', 23: 'Telnet',
        
        # Application Services
        1723: 'PPTP', 1194: 'OpenVPN', 500: 'IPSec', 4500: 'IPSec',
        6667: 'IRC', 6697: 'IRC-SSL', 25565: 'Minecraft', 27015: 'Steam',
        
        # Enterprise Services
        88: 'Kerberos', 389: 'LDAP', 636: 'LDAPS', 464: 'Kerberos', 749: 'Kerberos',
        
        # Monitoring & Management
        161: 'SNMP', 162: 'SNMP-Trap', 10050: 'Zabbix', 10051: 'Zabbix',
        5666: 'NRPE', 12489: 'NSClient++',
    }
    
    OS_SIGNATURES = {
        'windows': {
            'ports': [135, 139, 445, 3389],
            'banners': ['microsoft', 'windows', 'iis', 'exchange'],
            'ttl_range': (64, 128)
        },
        'linux': {
            'ports': [22],
            'banners': ['ubuntu', 'debian', 'centos', 'redhat', 'apache', 'nginx'],
            'ttl_range': (60, 64)
        },
        'unix': {
            'ports': [22, 111, 2049],
            'banners': ['unix', 'solaris', 'aix', 'hp-ux'],
            'ttl_range': (60, 64)
        },
        'cisco': {
            'ports': [23, 80, 443],
            'banners': ['cisco', 'ios'],
            'ttl_range': (240, 255)
        },
        'macos': {
            'ports': [22, 548, 631],
            'banners': ['darwin', 'macos', 'apple'],
            'ttl_range': (60, 64)
        }
    }

class AdvancedPortScanner:
    """Advanced port scanner with comprehensive reconnaissance capabilities"""
    
    def __init__(self):
        self.open_ports = []
        self.closed_ports = []
        self.filtered_ports = []
        self.service_info = {}
        self.os_detection = {}
        self.scan_statistics = {
            'start_time': None,
            'end_time': None,
            'total_ports': 0,
            'scan_rate': 0
        }
        self.vulnerability_hints = []
        
    def display_banner(self):
        """Display enhanced professional banner"""
        banner = f"""
{TerminalColors.CYAN}{TerminalColors.BOLD}
╔══════════════════════════════════════════════════════════════════════════╗
║                    ADVANCED PROFESSIONAL PORT SCANNER                    ║
║                         Network Reconnaissance Suite                     ║
║                              Version 3.0 Pro                            ║
║                          Enhanced OS Detection                           ║
╠══════════════════════════════════════════════════════════════════════════╣
║  Features: Multi-threaded Scanning | Service Enumeration | OS Detection ║
║           Banner Grabbing | Vulnerability Assessment | Report Export    ║
╚══════════════════════════════════════════════════════════════════════════╝
{TerminalColors.END}

{TerminalColors.YELLOW}[!] For educational and authorized testing purposes only{TerminalColors.END}
{TerminalColors.YELLOW}[!] Ensure you have permission to scan the target system{TerminalColors.END}
        """
        print(banner)
    
    def validate_target(self, target):
        """Enhanced target validation and resolution"""
        try:
            # Check if it's already an IP address
            ipaddress.ip_address(target)
            return target, target
        except ValueError:
            # Try to resolve hostname
            try:
                resolved_ip = socket.gethostbyname(target)
                print(f"{TerminalColors.GREEN}[+] Resolved {target} → {resolved_ip}{TerminalColors.END}")
                return target, resolved_ip
            except socket.gaierror:
                print(f"{TerminalColors.RED}[-] Failed to resolve hostname: {target}{TerminalColors.END}")
                return None, None
    
    def tcp_syn_scan(self, target, port, timeout=1):
        """Enhanced TCP SYN scan with better error handling"""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            
            # Set socket options for better performance
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            
            result = sock.connect_ex((target, port))
            sock.close()
            
            if result == 0:
                return 'open'
            elif result == 111:  # Connection refused
                return 'closed'
            else:
                return 'filtered'
                
        except socket.timeout:
            return 'filtered'
        except Exception:
            return 'filtered'
    
    def advanced_banner_grab(self, target, port, timeout=3):
        """Advanced banner grabbing with multiple probe techniques"""
        banners = []
        
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(timeout)
            sock.connect((target, port))
            
            # Define probe payloads for different services
            probes = {
                'http': b'GET / HTTP/1.1\r\nHost: ' + target.encode() + b'\r\nUser-Agent: Mozilla/5.0\r\n\r\n',
                'smtp': b'EHLO test.com\r\n',
                'ftp': b'USER anonymous\r\n',
                'ssh': b'SSH-2.0-Test\r\n',
                'telnet': b'\r\n',
                'pop3': b'USER test\r\n',
                'imap': b'A001 CAPABILITY\r\n',
                'generic': b'\r\n\r\n'
            }
            
            # Determine service type and use appropriate probe
            service_type = 'generic'
            if port in [80, 8080, 8000, 8443, 8888]:
                service_type = 'http'
            elif port == 25:
                service_type = 'smtp'
            elif port == 21:
                service_type = 'ftp'
            elif port == 22:
                service_type = 'ssh'
            elif port == 23:
                service_type = 'telnet'
            elif port == 110:
                service_type = 'pop3'
            elif port == 143:
                service_type = 'imap'
            
            # Send appropriate probe
            if service_type in probes:
                sock.send(probes[service_type])
            
            # Try to receive banner
            banner = sock.recv(2048).decode('utf-8', errors='ignore').strip()
            sock.close()
            
            if banner:
                return banner[:500]  # Limit banner length
            
        except Exception:
            pass
        
        return None
    
    def comprehensive_os_detection(self, target, open_ports):
        """Comprehensive OS detection using multiple fingerprinting techniques"""
        print(f"\n{TerminalColors.YELLOW}[*] Performing comprehensive OS detection...{TerminalColors.END}")
        
        os_scores = defaultdict(int)
        detection_methods = []
        
        # 1. TTL-based detection
        ttl_os = self.detect_os_by_ttl(target)
        if ttl_os:
            os_scores[ttl_os] += 3
            detection_methods.append(f"TTL fingerprinting: {ttl_os}")
        
        # 2. Port-based detection
        port_os = self.detect_os_by_ports(open_ports)
        for os_type in port_os:
            os_scores[os_type] += 2
            detection_methods.append(f"Port analysis: {os_type}")
        
        # 3. Banner-based detection
        banner_os = self.detect_os_by_banners()
        for os_type in banner_os:
            os_scores[os_type] += 4
            detection_methods.append(f"Banner analysis: {os_type}")
        
        # 4. Service combination analysis
        service_os = self.detect_os_by_service_combination(open_ports)
        for os_type in service_os:
            os_scores[os_type] += 2
            detection_methods.append(f"Service pattern: {os_type}")
        
        # Determine most likely OS
        if os_scores:
            most_likely_os = max(os_scores, key=os_scores.get)
            confidence = min(os_scores[most_likely_os] * 10, 90)  # Cap at 90%
            
            self.os_detection = {
                'most_likely': most_likely_os,
                'confidence': f"{confidence}%",
                'all_candidates': dict(os_scores),
                'detection_methods': detection_methods
            }
        else:
            self.os_detection = {
                'most_likely': 'Unknown',
                'confidence': '0%',
                'all_candidates': {},
                'detection_methods': ['No reliable indicators found']
            }
        
        return self.os_detection
    
    def detect_os_by_ttl(self, target):
        """Detect OS based on TTL values"""
        try:
            if platform.system().lower() == 'windows':
                cmd = ['ping', '-n', '1', target]
            else:
                cmd = ['ping', '-c', '1', target]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0:
                # Extract TTL value from output
                ttl_match = re.search(r'ttl=(\d+)', result.stdout, re.IGNORECASE)
                if ttl_match:
                    ttl = int(ttl_match.group(1))
                    
                    # Determine OS based on TTL
                    if ttl <= 64:
                        return 'Linux/Unix'
                    elif ttl <= 128:
                        return 'Windows'
                    elif ttl <= 255:
                        return 'Cisco/Network Device'
        except:
            pass
        
        return None
    
    def detect_os_by_ports(self, open_ports):
        """Detect OS based on characteristic port combinations"""
        detected_os = []
        
        for os_type, signatures in ServiceDatabase.OS_SIGNATURES.items():
            characteristic_ports = signatures['ports']
            matches = sum(1 for port in characteristic_ports if port in open_ports)
            
            if matches > 0:
                if os_type == 'windows' and matches >= 2:
                    detected_os.append('Windows')
                elif os_type == 'linux' and 22 in open_ports:
                    detected_os.append('Linux')
                elif matches >= 1:
                    detected_os.append(os_type.title())
        
        return detected_os
    
    def detect_os_by_banners(self):
        """Detect OS based on service banners"""
        detected_os = []
        
        for port, info in self.service_info.items():
            banner = info.get('banner', '').lower()
            if banner:
                for os_type, signatures in ServiceDatabase.OS_SIGNATURES.items():
                    for signature in signatures['banners']:
                        if signature in banner:
                            detected_os.append(os_type.title())
                            break
        
        return list(set(detected_os))
    
    def detect_os_by_service_combination(self, open_ports):
        """Detect OS based on service combinations"""
        detected_os = []
        
        # Windows-specific combinations
        if {135, 139, 445}.intersection(open_ports):
            detected_os.append('Windows')
        
        # Linux-specific combinations
        if 22 in open_ports and any(port in [80, 443, 25, 53] for port in open_ports):
            detected_os.append('Linux')
        
        # Network device indicators
        if {23, 80, 443}.intersection(open_ports) and not {22, 135, 139}.intersection(open_ports):
            detected_os.append('Network Device')
        
        return detected_os
    
    def vulnerability_assessment(self, target, open_ports):
        """Basic vulnerability assessment based on open ports"""
        vulnerabilities = []
        
        for port in open_ports:
            service_info = self.service_info.get(port, {})
            service = service_info.get('service', 'Unknown')
            banner = service_info.get('banner', '')
            
            # Check for common vulnerable services
            if port == 21 and 'ftp' in banner.lower():
                vulnerabilities.append(f"Port {port}: FTP service detected - Check for anonymous access")
            
            if port == 23:
                vulnerabilities.append(f"Port {port}: Telnet service - Unencrypted protocol")
            
            if port == 53:
                vulnerabilities.append(f"Port {port}: DNS service - Check for zone transfers")
            
            if port == 161:
                vulnerabilities.append(f"Port {port}: SNMP service - Check for default communities")
            
            if port == 445:
                vulnerabilities.append(f"Port {port}: SMB service - Check for null sessions")
            
            if port in [1433, 3306, 5432]:
                vulnerabilities.append(f"Port {port}: Database service exposed - Check access controls")
            
            if port == 3389:
                vulnerabilities.append(f"Port {port}: RDP service - Check for brute force protection")
        
        self.vulnerability_hints = vulnerabilities
        return vulnerabilities
    
    def scan_port_advanced(self, target, port, timeout=1):
        """Advanced port scanning with service detection"""
        status = self.tcp_syn_scan(target, port, timeout)
        
        if status == 'open':
            service_name = ServiceDatabase.COMMON_PORTS.get(port, 'Unknown')
            banner = self.advanced_banner_grab(target, port, timeout + 1)
            
            port_info = {
                'port': port,
                'status': status,
                'service': service_name,
                'banner': banner,
                'scan_time': time.time()
            }
            
            self.open_ports.append(port)
            self.service_info[port] = port_info
            
            return port_info
        else:
            if status == 'closed':
                self.closed_ports.append(port)
            else:
                self.filtered_ports.append(port)
            
            return None
    
    def execute_scan(self, target, ports, threads=100, timeout=1):
        """Execute the port scan with enhanced progress tracking"""
        print(f"\n{TerminalColors.CYAN}[*] Initiating advanced port scan...{TerminalColors.END}")
        print(f"{TerminalColors.CYAN}[*] Target: {target}{TerminalColors.END}")
        print(f"{TerminalColors.CYAN}[*] Ports: {len(ports)} total{TerminalColors.END}")
        print(f"{TerminalColors.CYAN}[*] Threads: {threads}{TerminalColors.END}")
        print(f"{TerminalColors.CYAN}[*] Timeout: {timeout}s{TerminalColors.END}")
        
        self.scan_statistics['start_time'] = time.time()
        self.scan_statistics['total_ports'] = len(ports)
        
        completed_count = 0
        
        with ThreadPoolExecutor(max_workers=threads) as executor:
            future_to_port = {
                executor.submit(self.scan_port_advanced, target, port, timeout): port 
                for port in ports
            }
            
            for future in as_completed(future_to_port):
                port = future_to_port[future]
                completed_count += 1
                
                try:
                    result = future.result()
                    if result:
                        status_color = TerminalColors.GREEN
                        banner_info = result['banner'][:60] if result['banner'] else 'No banner'
                        print(f"{status_color}[+] {port:5d}/tcp  {result['status']:<8} {result['service']:<15} {banner_info}{TerminalColors.END}")
                
                except Exception as e:
                    print(f"{TerminalColors.RED}[-] Error scanning port {port}: {str(e)[:50]}{TerminalColors.END}")
                
                # Progress indicator
                if completed_count % 100 == 0 or completed_count == len(ports):
                    progress = (completed_count / len(ports)) * 100
                    print(f"{TerminalColors.YELLOW}[*] Progress: {progress:.1f}% ({completed_count}/{len(ports)}){TerminalColors.END}")
        
        self.scan_statistics['end_time'] = time.time()
        scan_duration = self.scan_statistics['end_time'] - self.scan_statistics['start_time']
        self.scan_statistics['scan_rate'] = len(ports) / scan_duration if scan_duration > 0 else 0
        
        return self.open_ports
    
    def generate_comprehensive_report(self, target, hostname=None):
        """Generate comprehensive scan report"""
        print(f"\n{TerminalColors.BOLD}{TerminalColors.UNDERLINE}COMPREHENSIVE SCAN REPORT{TerminalColors.END}")
        print(f"{TerminalColors.CYAN}{'='*80}{TerminalColors.END}")
        
        # Target information
        print(f"\n{TerminalColors.BOLD}TARGET INFORMATION:{TerminalColors.END}")
        if hostname and hostname != target:
            print(f"Hostname: {TerminalColors.YELLOW}{hostname}{TerminalColors.END}")
        print(f"IP Address: {TerminalColors.YELLOW}{target}{TerminalColors.END}")
        print(f"Scan Date: {TerminalColors.YELLOW}{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}{TerminalColors.END}")
        
        # Scan statistics
        scan_duration = self.scan_statistics['end_time'] - self.scan_statistics['start_time']
        print(f"\n{TerminalColors.BOLD}SCAN STATISTICS:{TerminalColors.END}")
        print(f"Total ports scanned: {TerminalColors.YELLOW}{self.scan_statistics['total_ports']}{TerminalColors.END}")
        print(f"Scan duration: {TerminalColors.YELLOW}{scan_duration:.2f} seconds{TerminalColors.END}")
        print(f"Scan rate: {TerminalColors.YELLOW}{self.scan_statistics['scan_rate']:.1f} ports/sec{TerminalColors.END}")
        print(f"Open ports: {TerminalColors.GREEN}{len(self.open_ports)}{TerminalColors.END}")
        print(f"Closed ports: {TerminalColors.RED}{len(self.closed_ports)}{TerminalColors.END}")
        print(f"Filtered ports: {TerminalColors.YELLOW}{len(self.filtered_ports)}{TerminalColors.END}")
        
        # Port scan results
        if self.open_ports:
            print(f"\n{TerminalColors.BOLD}OPEN PORTS AND SERVICES:{TerminalColors.END}")
            print(f"{'PORT':<8} {'SERVICE':<15} {'BANNER'}")
            print(f"{'-'*8} {'-'*15} {'-'*50}")
            
            for port in sorted(self.open_ports):
                service_info = self.service_info.get(port, {})
                service = service_info.get('service', 'Unknown')
                banner = service_info.get('banner', 'No banner detected')
                
                if banner and len(banner) > 50:
                    banner = banner[:47] + "..."
                
                print(f"{port:<8} {service:<15} {banner}")
        
        # OS Detection results
        if self.os_detection:
            print(f"\n{TerminalColors.BOLD}OS DETECTION RESULTS:{TerminalColors.END}")
            print(f"Most likely OS: {TerminalColors.GREEN}{self.os_detection.get('most_likely', 'Unknown')}{TerminalColors.END}")
            print(f"Confidence: {TerminalColors.MAGENTA}{self.os_detection.get('confidence', '0%')}{TerminalColors.END}")
            
            if self.os_detection.get('detection_methods'):
                print(f"Detection methods:")
                for method in self.os_detection['detection_methods']:
                    print(f"  • {method}")
        
        # Vulnerability assessment
        if self.vulnerability_hints:
            print(f"\n{TerminalColors.BOLD}SECURITY ASSESSMENT:{TerminalColors.END}")
            print(f"{TerminalColors.RED}[!] Potential security concerns identified:{TerminalColors.END}")
            for vuln in self.vulnerability_hints:
                print(f"  • {vuln}")
    
    def export_results(self, target, hostname=None, filename=None):
        """Export scan results to JSON file"""
        if not filename:
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_target = target.replace('.', '_')
            filename = f"advanced_scan_{safe_target}_{timestamp}.json"
        
        scan_results = {
            'scan_info': {
                'target_ip': target,
                'target_hostname': hostname,
                'scan_date': datetime.now().isoformat(),
                'scanner_version': '3.0 Professional',
                'scan_duration': self.scan_statistics['end_time'] - self.scan_statistics['start_time'],
                'scan_rate': self.scan_statistics['scan_rate']
            },
            'port_scan': {
                'total_ports_scanned': self.scan_statistics['total_ports'],
                'open_ports': self.open_ports,
                'closed_ports_count': len(self.closed_ports),
                'filtered_ports_count': len(self.filtered_ports),
                'service_details': self.service_info
            },
            'os_detection': self.os_detection,
            'security_assessment': {
                'vulnerability_hints': self.vulnerability_hints
            }
        }
        
        try:
            with open(filename, 'w') as f:
                json.dump(scan_results, f, indent=2, default=str)
            print(f"\n{TerminalColors.GREEN}[+] Detailed results exported to: {filename}{TerminalColors.END}")
            return filename
        except Exception as e:
            print(f"\n{TerminalColors.RED}[-] Error exporting results: {e}{TerminalColors.END}")
            return None

def parse_port_specification(port_spec):
    """Parse port specification into list of ports"""
    ports = []
    
    for part in port_spec.split(','):
        part = part.strip()
        if '-' in part:
            start, end = map(int, part.split('-'))
            ports.extend(range(start, end + 1))
        else:
            ports.append(int(part))
    
    return sorted(list(set(ports)))  # Remove duplicates and sort

def main():
    parser = argparse.ArgumentParser(
        description='Advanced Professional Port Scanner with OS Detection',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Advanced Usage Examples:
  # Full port scan with OS detection
  python3 advanced_scanner.py -t 192.168.1.100 -p 1-65535 --threads 200

  # Quick service scan
  python3 advanced_scanner.py -t example.com -p 21,22,23,25,53,80,110,143,443,993,995

  # Stealth scan with extended timeout
  python3 advanced_scanner.py -t 10.0.0.1 -p 1-1000 --timeout 3 --threads 50

  # Complete assessment with export
  python3 advanced_scanner.py -t target.local -p 1-10000 --export --vuln-scan

  # Top 100 ports scan
  python3 advanced_scanner.py -t 192.168.1.1 --top-ports 100
        """
    )
    
    parser.add_argument('-t', '--target', required=True, 
                       help='Target IP address or hostname')
    parser.add_argument('-p', '--ports', 
                       help='Port specification (e.g., 1-1000, 22,80,443)')
    parser.add_argument('--top-ports', type=int, choices=[100, 1000], 
                       help='Scan top N most common ports')
    parser.add_argument('--threads', type=int, default=100, 
                       help='Number of scanning threads (default: 100)')
    parser.add_argument('--timeout', type=float, default=1, 
                       help='Connection timeout in seconds (default: 1)')
    parser.add_argument('--export', action='store_true', 
                       help='Export results to JSON file')
    parser.add_argument('--no-os', action='store_true', 
                       help='Skip OS detection phase')
    parser.add_argument('--vuln-scan', action='store_true', 
                       help='Include vulnerability assessment')
    parser.add_argument('--stealth', action='store_true', 
                       help='Enable stealth mode (slower but less detectable)')
    
    args = parser.parse_args()
    
    # Initialize scanner
    scanner = AdvancedPortScanner()
    scanner.display_banner()
    
    # Validate and resolve target
    hostname, target_ip = scanner.validate_target(args.target)
    if not target_ip:
        sys.exit(1)
    
    # Determine ports to scan
    if args.top_ports:
        # Get top N ports
        top_ports_100 = [21, 22, 23, 25, 53, 80, 110, 111, 135, 139, 143, 443, 993, 995, 1723, 3306, 3389, 5432, 5900, 8080]
        top_ports_1000 = list(range(1, 1001))
        
        if args.top_ports == 100:
            ports_to_scan = top_ports_100
        else:
            ports_to_scan = top_ports_1000
    elif args.ports:
        ports_to_scan = parse_port_specification(args.ports)
    else:
        # Default to common ports
        ports_to_scan = [21, 22, 23, 25, 53, 80, 110, 135, 139, 143, 443, 993, 995, 1433, 3306, 3389, 5432, 8080]
    
    # Apply stealth mode settings
    if args.stealth:
        args.threads = min(args.threads, 20)
        args.timeout = max(args.timeout, 2)
        print(f"{TerminalColors.YELLOW}[*] Stealth mode enabled - reduced threads and increased timeout{TerminalColors.END}")
    
    # Execute port scan
    try:
        open_ports = scanner.execute_scan(target_ip, ports_to_scan, args.threads, args.timeout)
        
        # Perform OS detection if requested
        if not args.no_os and open_ports:
            scanner.comprehensive_os_detection(target_ip, open_ports)
        
        # Perform vulnerability assessment if requested
        if args.vuln_scan and open_ports:
            print(f"\n{TerminalColors.YELLOW}[*] Performing vulnerability assessment...{TerminalColors.END}")
            scanner.vulnerability_assessment(target_ip, open_ports)
        
        # Generate comprehensive report
        scanner.generate_comprehensive_report(target_ip, hostname)
        
        # Export results if requested
        if args.export:
            scanner.export_results(target_ip, hostname)
        
        # Final summary
        print(f"\n{TerminalColors.BOLD}SCAN SUMMARY:{TerminalColors.END}")
        if open_ports:
            print(f"{TerminalColors.GREEN}[+] {len(open_ports)} open ports discovered{TerminalColors.END}")
            if scanner.os_detection.get('most_likely') != 'Unknown':
                print(f"{TerminalColors.GREEN}[+] Target OS: {scanner.os_detection['most_likely']} ({scanner.os_detection['confidence']} confidence){TerminalColors.END}")
            if scanner.vulnerability_hints:
                print(f"{TerminalColors.YELLOW}[!] {len(scanner.vulnerability_hints)} potential security concerns identified{TerminalColors.END}")
        else:
            print(f"{TerminalColors.YELLOW}[*] No open ports found in the scanned range{TerminalColors.END}")
        
        print(f"\n{TerminalColors.CYAN}[*] Advanced scan completed successfully!{TerminalColors.END}")
        print(f"{TerminalColors.CYAN}[*] Thank you for using Advanced Professional Port Scanner{TerminalColors.END}")
        
    except KeyboardInterrupt:
        print(f"\n{TerminalColors.RED}[!] Scan interrupted by user{TerminalColors.END}")
        print(f"{TerminalColors.YELLOW}[*] Partial results may be available{TerminalColors.END}")
        sys.exit(1)
    
    except Exception as e:
        print(f"\n{TerminalColors.RED}[!] Critical error during scan: {e}{TerminalColors.END}")
        print(f"{TerminalColors.YELLOW}[*] Please check your network connection and target accessibility{TerminalColors.END}")
        sys.exit(1)

def display_help_examples():
    """Display detailed usage examples"""
    examples = f"""
{TerminalColors.BOLD}{TerminalColors.CYAN}ADVANCED PORT SCANNER - USAGE EXAMPLES{TerminalColors.END}

{TerminalColors.BOLD}Basic Scans:{TerminalColors.END}
  # Scan common ports
  python3 scanner.py -t 192.168.1.100

  # Scan specific port range
  python3 scanner.py -t example.com -p 1-1000

  # Scan specific ports
  python3 scanner.py -t 10.0.0.1 -p 22,80,443,8080

{TerminalColors.BOLD}Advanced Scans:{TerminalColors.END}
  # Full port scan with high thread count
  python3 scanner.py -t 192.168.1.100 -p 1-65535 --threads 500

  # Top 1000 ports with OS detection
  python3 scanner.py -t target.com --top-ports 1000

  # Stealth scan (slower, less detectable)
  python3 scanner.py -t 192.168.1.100 -p 1-1000 --stealth

{TerminalColors.BOLD}Professional Assessments:{TerminalColors.END}
  # Complete security assessment
  python3 scanner.py -t 10.0.0.1 -p 1-10000 --vuln-scan --export

  # Network device scan
  python3 scanner.py -t 192.168.1.1 -p 21-25,53,80,161,443,8080 --timeout 3

{TerminalColors.BOLD}Performance Tuning:{TerminalColors.END}
  # High-speed scan
  python3 scanner.py -t 192.168.1.100 -p 1-1000 --threads 200 --timeout 0.5

  # Reliable scan through firewall
  python3 scanner.py -t external-target.com -p 80,443,8080 --timeout 5 --threads 20

{TerminalColors.BOLD}Output Options:{TerminalColors.END}
  # Export detailed results
  python3 scanner.py -t 192.168.1.100 -p 1-1000 --export

  # Skip OS detection for faster results
  python3 scanner.py -t 192.168.1.100 -p 1-1000 --no-os
    """
    print(examples)

if __name__ == "__main__":
    try:
        # Check if help examples requested
        if len(sys.argv) > 1 and sys.argv[1] in ['--examples', '--help-examples']:
            display_help_examples()
            sys.exit(0)
        
        main()
        
    except KeyboardInterrupt:
        print(f"\n{TerminalColors.RED}[!] Program interrupted by user{TerminalColors.END}")
        sys.exit(1)
    except Exception as e:
        print(f"\n{TerminalColors.RED}[!] Unexpected error: {e}{TerminalColors.END}")
        sys.exit(1)




