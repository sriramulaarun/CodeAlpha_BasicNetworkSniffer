# 🛡️ Aegis Net Sniffer // Security Operations Center (SOC) Dashboard

A professional, cybersecurity-themed **Basic Network Sniffer Dashboard** designed for the **CodeAlpha Cyber Security Internship**.

Aegis Net Sniffer is a passive network analysis tool that captures, decodes, and inspects local network packets in real-time. It exposes a modern, high-tech dark mode Web UI resembling a security analyst's SOC panel, featuring live-updating charts, traffic density indicators, and automated packet filtering.

---

## ⚡ Key Features

- **Real-Time Network Sniffing**: Uses **Scapy** to listen on local network adapters, capture raw packets, and inspect Ethernet, IPv4, IPv6, TCP, UDP, and ICMP headers.
- **Automatic Simulation Fallback**: Raw socket capture on Windows/Linux requires root/administrator privileges and packet capture drivers (like Npcap). Aegis Sniffer automatically detects configuration blocks and falls back to a **Simulated Traffic Generator** containing realistic, pre-analyzed packet flows so the project is always ready to demo.
- **SOC Glassmorphism Web UI**: Built with a sleek cybersecurity dark-theme layout using custom glassmorphism components (translucent blur, neon accent borders, Fira Code telemetry fonts).
- **Interactive Data Visualization**:
  - **Protocol Distribution**: Dynamic doughnut chart tracking TCP vs. UDP vs. ICMP percentages.
  - **Traffic Density**: Real-time Line/Area chart displaying packet intake rates (packets per second).
- **Passive Threat Analysis Heuristics**:
  - **Insecure Protocols**: Automatically raises warnings for unencrypted protocols like Telnet (Port 23) and FTP (Port 21).
  - **Port Scan Reconnaissance**: Detects IPs mapping more than 5 distinct destination ports within a 5-second window, marking the status as **Suspicious**.
  - **Flooding/DDoS Warning**: Triggers warnings if an IP source fires more than 40 packets within a 5-second threshold.
- **Advanced Packet Logger**: A searchable, filterable logs table listing timestamp, source/destination sockets, protocol size, dynamic inspection summaries, and threat status pills.

---

## 🛠️ Tech Stack

- **Backend**: Python 3, Flask (API Server & Routing)
- **Packet Engine**: Scapy (Core packet sniffer, decoder, parser)
- **Frontend**: HTML5 (Semantic Structure), CSS3 (Custom Grid, Glassmorphism, Animations), Vanilla JavaScript (API long-polling, state control, DOM mapping)
- **CSS Framework**: Bootstrap 5 (Responsive utilities)
- **Visualization**: Chart.js (Real-time charts rendering)
- **Icons & Fonts**: FontAwesome v6, Google Fonts (Outfit & Fira Code)

---

## 📂 Project Structure

```text
CodeAlpha_BasicNetworkSniffer/
│
├── app.py                     # Flask Web Server & Endpoint APIs
├── sniffer.py                 # Scapy Listener & Simulation fallback engine
├── requirements.txt           # Python dependency specifications
│
├── static/
│   ├── css/
│   │   └── style.css          # Custom Glassmorphism SOC Styling
│   └── js/
│       └── script.js          # Chart.js, Polling, DOM render logic
│
├── templates/
│   └── index.html             # Dashboard User Interface Layout
│
├── screenshots/               # Folder for demonstration assets
│
└── README.md                  # Installation & documentation guide
```

---

## 🚀 Installation & Setup

### Prerequisites
- **Python 3.x** installed.
- **Npcap (Windows Only)**: To perform live capture, you must download and install [Npcap](https://npcap.com/). Select the option **"Install Npcap in WinPcap API-compatible mode"** during installation.

### Step 1: Clone the Repository
```bash
git clone https://github.com/sriramulaarun/CodeAlpha_BasicNetworkSniffer.git
cd CodeAlpha_BasicNetworkSniffer
```

### Step 2: Install Dependencies
Create a virtual environment and install the required libraries:
```bash
# Create virtual environment
python -m venv venv

# Activate on Windows
venv\Scripts\activate

# Activate on macOS/Linux
source venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

---

## 💻 Running the Application

### Option A: Running in Simulated / Demo Mode (No Admin Rights Needed)
To run the server in simulated mode to evaluate the dashboard layout and features without administrative privileges or Npcap:
```bash
python app.py
```
Open **`http://127.0.0.1:5000`** in your browser and click **Start Capture**. You will see a warning banner denoting "Simulation Mode", and mock packets will begin streaming.

### Option B: Running Live Network Capture (Requires Privileges)
To bind Scapy to your physical network adapters and sniff live traffic:
1. Make sure **Npcap** is installed (Windows).
2. Open your terminal **as Administrator** (Windows) or use `sudo` (Linux/macOS).
3. Activate the virtual environment.
4. Run the Flask server:
```bash
# Windows (Run Cmd/PowerShell as Administrator)
python app.py

# Linux/macOS
sudo venv/bin/python app.py
```
Open **`http://127.0.0.1:5000`** and click **Start Capture**. The status badge will display `LIVE (Promiscuous)` and show active network card traffic.

---

## 🛡️ Cybersecurity Analysis Logic

Aegis Net Sniffer incorporates basic intrusion detection system (IDS) features:
1. **Normal Traffic**: Highlighted in standard dark tones. Includes HTTPS (Port 443), secure DNS query, and standard outbound requests.
2. **Warning Logs**: Highlighted in Amber. Triggers for plain-text logins, oversized payloads, or large ICMP echo requests.
3. **Suspicious Alerts**: Highlighted in Red. Triggered when host traffic patterns violate security safety margins:
   ```text
   Stateful Tracker Heuristics:
   IF Unique_Ports(Source_IP) >= 5 within 5 seconds -> Tag as 'Suspicious' (Port Scan Reconnaissance)
   IF Packet_Count(Source_IP) > 40 within 5 seconds -> Tag as 'Suspicious' (Traffic Flooding)
   ```

---

## 🔮 Future Enhancements

- **PCAP File Export**: Enable downloading captured streams as standard `.pcap` files for inspection in Wireshark.
- **GeoIP Lookup**: Integrate a geolocation database to map public IP source locations on a world map overlay.
- **Payload Hex Viewer**: Expand packet rows to inspect raw hex and ASCII payloads.
- **Custom Filtering Rules**: Write custom Snort-like rules to trigger alarms on specific byte signatures.

---

## 📝 License
Distributed under the MIT License. See `LICENSE` for more information.

*Developed as part of the CodeAlpha Cyber Security Internship program.*
