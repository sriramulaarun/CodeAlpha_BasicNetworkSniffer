# CodeAlpha Cyber Security Internship: Technical Project Report

**Project Name:** Aegis Network Sniffer & SOC Dashboard (Basic Network Sniffer)  
**Track:** Cyber Security  
**Internship Role:** Cyber Security Intern  
**Documentation Version:** 1.0.0  

---

## Table of Contents
1. [Executive Summary](#1-executive-summary)
2. [System Architecture & Flow](#2-system-architecture--flow)
3. [Backend Engineering Details](#3-backend-engineering-details)
4. [Frontend Design & UX](#4-frontend-design--ux)
5. [Intrusion Detection System (IDS) Heuristics](#5-intrusion-detection-system-ids-heuristics)
6. [Deployment & Verification Guidelines](#6-deployment--verification-guidelines)
7. [Academic & Technical References](#7-academic--technical-references)

---

## 1. Executive Summary
During the CodeAlpha Cyber Security Internship, a core requirement was to construct a **Basic Network Sniffer** to observe and catalog local area network traffic. Aegis Network Sniffer was created to answer this requirement by developing a complete, passive packet capture solution that integrates a powerful Scapy engine backend with a modern, glassmorphism-themed Security Operations Center (SOC) dashboard. 

The project solves the common issue of deployment blocks (due to administrative rights or missing network capture drivers like Npcap) by building a dual-mode engine. If raw sockets are unavailable, the engine gracefully transitions to an automated traffic simulation framework that mimics live packets. This ensures the project remains demonstratable and functional in any local or cloud environment.

---

## 2. System Architecture & Flow

The sniffer operates as a multi-threaded web application. The backend manages packet streams and state while the frontend pulls incremental changes over AJAX.

### Architecture Diagram
```text
  [ Network Interfaces (NIC) ]
              │
              ▼ (Requires Admin & Npcap/WinPcap)
  [ Scapy Sniffing Engine ] ───(If fails/no permission)───► [ Simulated Packet Loop ]
              │                                                     │
              └─────────────────────┬───────────────────────────────┘
                                    │ (Parsed Packet Object)
                                    ▼
                      [ Thread-Safe Collections.Deque ]
                                    │
                                    ▼
                       [ Flask REST API Endpoints ]
                                    │
            ┌───────────────────────┴───────────────────────┐
            │ GET /api/packets?since_id=X                   │ GET /api/status
            ▼                                               ▼
  [ JS Long-Polling Loop ]                       [ JS Status & Metrics Sync ]
            │                                               │
            ▼                                               ▼
  [ Update Logs Table ]                         [ Update Chart.js & Widgets ]
```

### Process Lifecycle
1. **Initiation**: The user clicks the **Start Capture** button.
2. **Spawning**: The Flask backend launches a background daemon thread (`_run_sniffer` in `sniffer.py`).
3. **Binding & Decoding**:
   - The thread attempts to bind Scapy's socket receiver to the primary interface.
   - If binding succeeds, packets are parsed live. Layer 3 (IP/IPv6) and Layer 4 (TCP/UDP/ICMP) headers are dissected.
   - If binding fails (due to driver issues or permission limits), the thread logs the error, switches the mode status to `simulated`, and initiates a mock loop generating realistic HTTP, HTTPS, DNS, Ping, and attack vectors.
4. **Buffering**: Extracted packet statistics and metadata are appended to a ring buffer (`collections.deque`, limit = 1000) using a thread lock to prevent data corruption.
5. **Consumption**: The browser client makes a request to `/api/status` and `/api/packets` every 1.5 seconds.
   - To optimize latency and overhead, the client uses a **delta-pull mechanism**. It appends the `since_id` parameter to its query, receiving only new packets captured since the last polling frame.

---

## 3. Backend Engineering Details

### Packet Capture & Thread Safety
Python's standard Global Interpreter Lock (GIL) and Flask's multi-threaded local development server require robust thread safety when sharing objects. 
- **Thread Lock**: The class `NetworkSniffer` utilizes a `threading.Lock()` to secure mutations to the packet list and the aggregate statistics dictionaries.
- **Ring Buffer**: A `collections.deque` with a `maxlen` limit of 1000 is used. A deque is ideal for telemetry streams because it provides $O(1)$ performance for appends and automatically discards the oldest elements when the size limit is exceeded. This acts as a circuit breaker, preventing memory leaks during long-running capture sessions.

### Protocol Dissection
Scapy parses raw bytes into layers. Aegis Net Sniffer inspects:
- **Ethernet (Layer 2)**: Extracts frames.
- **IP/IPv6 (Layer 3)**: Extracts Source and Destination IP addresses and Protocol type indicators (ICMP, TCP, UDP).
- **TCP/UDP (Layer 4)**: Dissects source and destination ports. It maps standard port signatures to human-readable information strings (e.g., Port 443 → HTTPS, Port 53 → DNS).

---

## 4. Frontend Design & UX

The user interface was built to mirror a modern security dashboard, departing from standard default styling in favor of rich visual feedback:
- **Aesthetic Theme**: High-contrast dark mode using dark-slate gradients, neon highlights (cyan, electric blue, green, and red), and the monospaced font *Fira Code* to display packet dumps and addresses.
- **Glassmorphism Panels**: UI cards utilize `backdrop-filter: blur(10px)` with translucent borders to create a layered glass effect, reducing visual clutter.
- **Micro-Animations**: Features glowing pulse states on buttons, fade-in animations on table insertions, and flashing icons on threat alerts.
- **Telemetry Charts**:
  - A Chart.js **Doughnut Chart** displays protocol proportions.
  - A Chart.js **Line/Area Chart** maps traffic volume, recalculating packets-per-second (PPS) rates in real-time.

---

## 5. Intrusion Detection System (IDS) Heuristics

Aegis Net Sniffer behaves as a lightweight passive IDS by running heuristic filters on incoming traffic:

| Threat Category | Severity | Heuristics Rule | Trigger Description |
| :--- | :--- | :--- | :--- |
| **Insecure Protocols** | Warning | `TCP port == 21` OR `TCP port == 23` | Detects FTP or Telnet connections transmitting credentials in plain text. |
| **Oversized Payloads** | Warning | `Packet Size > 1480 bytes` (Non-Web Ports) | Detects potential ICMP fragmentation attacks or large data transfers on non-standard ports. |
| **Traffic Flooding** | Suspicious | `Packet Count (Source IP) > 40` in 5 seconds | Highlights potential DDoS, UDP flood, or ICMP flood activity. |
| **Port Scan Reconnaissance** | Suspicious | `Unique Ports (Source IP) >= 5` in 5 seconds | Tracks destination ports hit by a single IP. Alerts on rapid, multi-port scans. |

---

## 6. Deployment & Verification Guidelines

To verify the application:
1. Ensure the backend handles invalid parameters gracefully.
2. Manually test the Flask routes using browser developer tools or Postman.
3. Validate simulated traffic to confirm that chart slices update proportionally and the live logger flags security triggers (e.g., scanning alarms or Telnet warnings).
4. Run live captures as Administrator to verify that Scapy successfully intercepts loopback or external interface traffic.

---

## 7. Academic & Technical References

1. **RFC 791 (Internet Protocol v4)**: Explains packet structure, source/destination fields, and proto mapping.
2. **RFC 793 (Transmission Control Protocol)**: Governs TCP flags, socket states, and connection tracking.
3. **Scapy Core Documentation**: Explains socket management and frame decoding loops.
4. **Flask Engine Architecture**: Explains multi-threaded WSGI dispatching and JSON API serialization.
