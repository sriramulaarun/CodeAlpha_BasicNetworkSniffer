import threading
import time
import random
from datetime import datetime
import collections

# Import Scapy components safely
try:
    from scapy.all import sniff, IP, IPv6, TCP, UDP, ICMP, ARP
    SCAPY_AVAILABLE = True
except Exception as e:
    SCAPY_AVAILABLE = False
    print(f"Scapy import warning/error: {e}")

class NetworkSniffer:
    def __init__(self, max_buffer_size=1000):
        self.max_buffer_size = max_buffer_size
        self.packets = collections.deque(maxlen=max_buffer_size)
        self.packet_counter = 0
        self.is_running = False
        self.sniffer_thread = None
        self.stop_event = threading.Event()
        
        # Stats dictionary
        self.stats = {
            "total": 0,
            "tcp": 0,
            "udp": 0,
            "icmp": 0,
            "other": 0,
            "threats": {
                "normal": 0,
                "warning": 0,
                "suspicious": 0
            }
        }
        
        self.lock = threading.Lock()
        self.mode = "idle"  # "live", "simulated", "idle"
        self.error_message = None
        
        # Simple threat detection state tracking
        self.recent_ips = collections.defaultdict(list)  # IP -> list of timestamps
        self.port_scan_tracker = collections.defaultdict(set)  # IP -> set of destination ports scanned

    def start(self):
        with self.lock:
            if self.is_running:
                return False
            
            self.is_running = True
            self.stop_event.clear()
            self.error_message = None
            
            # Spawn worker thread
            self.sniffer_thread = threading.Thread(target=self._run_sniffer)
            self.sniffer_thread.daemon = True
            self.sniffer_thread.start()
            return True

    def stop(self):
        with self.lock:
            if not self.is_running:
                return False
            self.is_running = False
            self.stop_event.set()
            return True

    def clear(self):
        with self.lock:
            self.packets.clear()
            self.packet_counter = 0
            self.stats = {
                "total": 0,
                "tcp": 0,
                "udp": 0,
                "icmp": 0,
                "other": 0,
                "threats": {
                    "normal": 0,
                    "warning": 0,
                    "suspicious": 0
                }
            }
            self.recent_ips.clear()
            self.port_scan_tracker.clear()
            return True

    def get_status(self):
        with self.lock:
            return {
                "is_running": self.is_running,
                "mode": self.mode,
                "error": self.error_message,
                "total_packets": self.stats["total"]
            }

    def get_packets(self, since_id=None, limit=100):
        with self.lock:
            packets_list = list(self.packets)
            
        if since_id is not None:
            try:
                since_id = int(since_id)
                packets_list = [p for p in packets_list if p["id"] > since_id]
            except ValueError:
                pass
                
        return packets_list[-limit:]

    def get_stats(self):
        with self.lock:
            return self.stats.copy()

    def _run_sniffer(self):
        """Main thread loop trying live Scapy capture and falling back to simulation on failure."""
        if not SCAPY_AVAILABLE:
            self._start_simulation("Scapy library is not available or failed to import.")
            return

        # Attempt to sniff a single packet to verify raw socket privileges/npcap presence
        try:
            self.mode = "live"
            # Attempt to run a brief sniffing check (timeout 0.5s)
            sniff(count=1, timeout=0.5, store=0)
        except Exception as e:
            # Catch raw socket / npcap issues and switch to simulation fallback
            self.error_message = str(e)
            self._start_simulation(f"Scapy failed to bind to raw socket: {e}. Switching to simulation fallback.")
            return

        # If live sniff works, enter the live sniff loop
        print("[BACKEND] Raw socket capture initialized successfully. Live sniffing running...")
        while not self.stop_event.is_set():
            try:
                # Sniff in small windows to regularly check stop_event
                sniff(prn=self._process_scapy_packet, timeout=1.0, store=0)
            except Exception as e:
                print(f"[BACKEND] Error during live capture: {e}")
                self.error_message = str(e)
                self._start_simulation(f"Live capture error occurred: {e}. Falling back to simulation.")
                break

    def _start_simulation(self, reason):
        print(f"[BACKEND] Starting simulation mode. Reason: {reason}")
        self.mode = "simulated"
        
        # Simulated IPs
        local_ips = ["192.168.1.15", "192.168.1.102", "192.168.1.55", "10.0.0.12"]
        public_servers = ["8.8.8.8", "1.1.1.1", "142.250.190.46", "34.210.15.22", "157.240.22.35"]
        malicious_ips = ["185.220.101.5", "45.227.254.12", "91.240.118.15", "198.51.100.42"]
        
        protocols = ["TCP", "UDP", "ICMP"]
        
        while not self.stop_event.is_set():
            # Random sleep to mimic network packet frequencies
            time.sleep(random.uniform(0.1, 0.7))
            
            # Generate simulated packet data
            proto = random.choice(protocols)
            size = random.randint(40, 1500)
            
            # Formulate source/dest based on simulated scenarios
            scenario = random.choices(
                ["normal_web", "dns_lookup", "ping", "suspicious_port_scan", "suspicious_ssh_brute", "suspicious_payload"],
                weights=[60, 20, 10, 4, 3, 3],
                k=1
            )[0]
            
            src = random.choice(local_ips)
            dst = random.choice(public_servers)
            sport = random.randint(49152, 65535)
            dport = 443
            info = ""
            status = "Normal"
            
            if scenario == "normal_web":
                dport = random.choice([80, 443])
                if dport == 443:
                    info = f"HTTPS Connection [TLS Handshake Client Hello]"
                else:
                    info = f"HTTP GET /index.html (Status: 200 OK)"
            elif scenario == "dns_lookup":
                proto = "UDP"
                dst = random.choice(["8.8.8.8", "1.1.1.1"])
                dport = 53
                info = f"DNS Standard Query A {random.choice(['google.com', 'github.com', 'codealpha.org', 'netflix.com'])}"
            elif scenario == "ping":
                proto = "ICMP"
                dst = "8.8.8.8"
                dport = 0
                info = "ICMP Echo Request (Ping)"
                # 10% chance of a warning ping size
                if random.random() < 0.15:
                    size = 1450
                    info = "ICMP Echo Request - Large Packet Size"
                    status = "Warning"
            elif scenario == "suspicious_port_scan":
                src = random.choice(malicious_ips)
                dst = random.choice(local_ips)
                # Scanning sequential port range
                scanned_port = random.choice([21, 22, 23, 80, 443, 8080, 3306])
                dport = scanned_port
                info = f"Potential Reconnaissance: Port Scan detected on Port {scanned_port}"
                status = "Suspicious"
            elif scenario == "suspicious_ssh_brute":
                src = random.choice(malicious_ips)
                dst = "192.168.1.15"
                dport = 22
                info = "SSH Brute Force Attempt: Multiple failed connections"
                status = "Suspicious"
            elif scenario == "suspicious_payload":
                src = random.choice(local_ips)
                dst = random.choice(public_servers)
                dport = 80
                info = "HTTP POST /login - Suspicious Payload Syntax (SQLi/XSS token detected)"
                status = "Warning" if random.random() < 0.5 else "Suspicious"
                
            # Randomize swapping source/destination to simulate 2-way traffic
            if random.random() < 0.4 and scenario not in ["suspicious_port_scan", "suspicious_ssh_brute"]:
                src, dst = dst, src
                sport, dport = dport, sport

            # Insert packet
            packet_data = {
                "id": self._increment_counter(),
                "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
                "src": src,
                "dst": dst,
                "proto": proto,
                "sport": sport,
                "dport": dport,
                "size": size,
                "info": info,
                "status": status
            }
            
            self._save_packet(packet_data)

    def _process_scapy_packet(self, packet):
        """Parses a live Scapy packet and extracts features for UI consumption."""
        if not packet.haslayer(IP) and not packet.haslayer(IPv6):
            return

        proto_str = "Other"
        src_ip = ""
        dst_ip = ""
        sport = 0
        dport = 0
        info_str = packet.summary()
        status_str = "Normal"

        # IP Layer Extraction
        if packet.haslayer(IP):
            src_ip = packet[IP].src
            dst_ip = packet[IP].dst
            proto_num = packet[IP].proto
            if proto_num == 6:
                proto_str = "TCP"
            elif proto_num == 17:
                proto_str = "UDP"
            elif proto_num == 1:
                proto_str = "ICMP"
        elif packet.haslayer(IPv6):
            src_ip = packet[IPv6].src
            dst_ip = packet[IPv6].dst
            # IPv6 Next Header
            nh = packet[IPv6].nh
            if nh == 6:
                proto_str = "TCP"
            elif nh == 17:
                proto_str = "UDP"
            elif nh == 58:
                proto_str = "ICMP"  # ICMPv6

        # Port Extraction & Context Summary
        if packet.haslayer(TCP):
            proto_str = "TCP"
            sport = packet[TCP].sport
            dport = packet[TCP].dport
            info_str = f"TCP Connection: Port {sport} → {dport}"
            
            # Detect TLS/SSL
            if sport == 443 or dport == 443:
                info_str = "HTTPS Secure Web Traffic"
            elif sport == 80 or dport == 80:
                info_str = "HTTP Plaintext Web Traffic"
            elif sport == 22 or dport == 22:
                info_str = "SSH Remote Terminal Session"
            elif sport == 23 or dport == 23:
                info_str = "Telnet Plaintext Terminal (Insecure)"
                status_str = "Warning"

        elif packet.haslayer(UDP):
            proto_str = "UDP"
            sport = packet[UDP].sport
            dport = packet[UDP].dport
            info_str = f"UDP Datagram: Port {sport} → {dport}"
            
            if sport == 53 or dport == 53:
                info_str = "DNS Name Resolution Lookup"
            elif sport == 67 or sport == 68 or dport == 67 or dport == 68:
                info_str = "DHCP Address Assignment Traffic"

        elif packet.haslayer(ICMP):
            proto_str = "ICMP"
            info_str = "ICMP Network Diagnostics Control Message"

        # Apply cybersecurity threat heuristics
        status_str, parsed_info = self._analyze_threat(src_ip, dst_ip, proto_str, dport, len(packet), info_str)
        if parsed_info:
            info_str = parsed_info

        packet_data = {
            "id": self._increment_counter(),
            "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            "src": src_ip,
            "dst": dst_ip,
            "proto": proto_str,
            "sport": sport,
            "dport": dport,
            "size": len(packet),
            "info": info_str,
            "status": status_str
        }
        
        self._save_packet(packet_data)

    def _analyze_threat(self, src, dst, proto, dport, size, summary):
        """Analyzes a packet for warning or suspicious thresholds."""
        status = "Normal"
        info_override = None

        # 1. Flag insecure protocols
        if proto == "TCP" and dport == 23:
            status = "Warning"
            info_override = "Warning: Insecure Protocol (Telnet) connection attempt"
        elif proto == "TCP" and dport == 21:
            status = "Warning"
            info_override = "Warning: Unencrypted FTP connection attempt"
            
        # 2. Flag oversized packets (could be data exfiltration / payload padding)
        elif size > 1480 and proto in ["TCP", "UDP"]:
            # If it's a standard MTU packet size it can be Normal, but if it has weird ports let's label Warning
            if dport not in [80, 443]:
                status = "Warning"
                info_override = f"Oversized payload transmission ({size} bytes) on port {dport}"

        # 3. Simple Port Scan heuristics (Stateful tracking)
        if src and dport > 0:
            now = time.time()
            # Clean old records
            self.recent_ips[src] = [t for t in self.recent_ips[src] if now - t < 5.0]
            self.recent_ips[src].append(now)
            
            # Track destination ports scanned
            self.port_scan_tracker[src].add(dport)
            
            # If an IP hits 5+ different ports in 5 seconds -> Potential Port Scan
            if len(self.port_scan_tracker[src]) >= 5:
                status = "Suspicious"
                info_override = f"Recon Alert: Port Scanning detected from {src} ({len(self.port_scan_tracker[src])} ports)"
            # If an IP generates 30+ packets in 5 seconds -> Flood Warning
            elif len(self.recent_ips[src]) > 40:
                status = "Suspicious"
                info_override = f"Traffic Alert: High packet volume (flooding) from {src}"

        return status, info_override

    def _increment_counter(self):
        with self.lock:
            self.packet_counter += 1
            return self.packet_counter

    def _save_packet(self, packet_data):
        with self.lock:
            self.packets.append(packet_data)
            
            # Update stats
            self.stats["total"] += 1
            
            proto = packet_data["proto"].lower()
            if proto in ["tcp", "udp", "icmp"]:
                self.stats[proto] += 1
            else:
                self.stats["other"] += 1
                
            status = packet_data["status"].lower()
            if status in self.stats["threats"]:
                self.stats["threats"][status] += 1
