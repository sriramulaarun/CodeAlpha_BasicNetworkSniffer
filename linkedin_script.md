# LinkedIn Video Presentation Script: Aegis Network Sniffer

**Target Duration:** ~3 Minutes (180 Seconds)  
**Topic:** Basic Network Sniffer SOC Dashboard (CodeAlpha Cyber Security Internship)  
**Tone:** Professional, Confident, Engineering-Focused  

---

## 🎬 Pre-Video Recording Check:
1. Open a browser and load the Aegis Dashboard (`http://127.0.0.1:5050`).
2. Make sure the capture is **stopped** initially so you can start it live on camera.
3. If recording a screen capture, show your face in a corner bubble (using tools like Loom, OBS, or Zoom) to maximize engagement.

---

## ⏱️ Video Script Outline

| Time | Screen/Visual Cue | Spoken Script |
| :--- | :--- | :--- |
| **0:00 - 0:30** | **Show your webcam + Dashboard screen (inactive).** Hover cursor near the Aegis Sniffer logo. | "Hi everyone! Today, I’m excited to share a project I built during my Cyber Security Internship at CodeAlpha: **Aegis Net Sniffer**—a real-time network traffic analyzer and SOC dashboard.<br><br>As security engineers, understanding network flows is crucial for threat detection. I wanted to build a tool that didn't just sniff packets in a boring terminal, but presented them in a professional, visual interface that mimics a real Security Operations Center." |
| **0:30 - 1:00** | **Click "Start Capture".** Watch the numbers roll in. Show the status badge changing to green. | "Let’s start the capture. You can see the engine immediately starts parsing packet streams. Aegis is built with a **Python Flask** backend and uses **Scapy** for deep packet inspection.<br><br>One of the key engineering challenges I solved here was deployment flexibility. If you run this in a restricted environment without Admin privileges or capture drivers, Aegis automatically detects that and falls back to a **Simulated Traffic Mode** generating realistic flows, keeping the system fully interactive and testable." |
| **1:00 - 1:40** | **Scroll down to the packet table.** Hover over the color-coded rows (Normal, Warning, Suspicious). | "If we look at our live stream table, we see packet metadata including timestamps, source and destination IP sockets, protocols, and sizes. <br><br>But Aegis does more than just list packets—it runs passive **Intrusion Detection Heuristics**. For example, it flags unencrypted protocols like FTP and Telnet as **Warnings**, and statefully tracks source IPs. If an IP scans 5 or more ports in a 5-second window, Aegis triggers a red **Suspicious** alert for Port Scanning, simulating real-world recon detection." |
| **1:40 - 2:10** | **Scroll up to the Charts section.** Show the Pie Chart and Line Chart updating dynamically. | "All this telemetry feeds directly into our analytics panel. On the left, we have a **Chart.js Doughnut Chart** rendering real-time protocol distributions—showing the proportions of TCP, UDP, and ICMP traffic. <br><br>On the right, we have a **Line Chart** displaying traffic density. By calculating packet intake rates, the graph updates dynamically, helping analysts identify anomalous traffic spikes or potential flooding attacks in progress." |
| **2:10 - 2:40** | **Toggle filters in the dropdowns.** (Select 'TCP' or 'Suspicious' and watch the table update). | "We can also filter our logs on the fly. By selecting 'Suspicious' or a specific protocol like TCP, the interface filters the buffer in real time without refreshing the page. <br><br>This frontend is styled using **Bootstrap 5** and custom CSS to achieve a clean **glassmorphism** design, ensuring that telemetry is easy to read while maintaining a modern, cybersecurity-themed layout." |
| **2:40 - 3:00** | **Show your webcam full screen (or hover over the final footer).** | "Building this sniffer was a fantastic experience in combining low-level packet analysis with multi-threaded Python backend engineering and modern UI/UX design. <br><br>The complete codebase is available on my GitHub. I want to thank the team at **CodeAlpha** for this challenging internship assignment. I’d love to hear your feedback in the comments. Thank you!" |

---

## 💡 Pro-Tips for Recording:
- **Practice the flow**: Do a quick 1-minute dry run of starting the capture, letting charts load, and changing filters to make sure everything transitions smoothly.
- **Microphone Check**: Ensure you have clear audio—high-quality audio makes a massive difference in how professional your presentation feels!
- **Share the Code**: In your actual LinkedIn text post, make sure to link the GitHub repository link and write a brief summary highlighting your tech stack (Python, Flask, Scapy, Chart.js, CSS Glassmorphism).
