/* ==========================================================================
   AEGIS SNIFFER - CORE FOREGROUND SCRIPT
   ========================================================================== */

document.addEventListener('DOMContentLoaded', () => {
    // State Variables
    let lastPacketId = 0;
    let packetsBuffer = []; // Local cache of recent packets (max 500)
    const maxBufferSize = 500;
    let isRunning = false;
    let pollIntervalId = null;
    let lastPollTime = Date.now();
    
    // Chart instances
    let protocolChart = null;
    let volumeChart = null;
    
    // Historical arrays for Traffic Density chart (last 20 intervals)
    const trafficHistory = Array(20).fill(0);
    const trafficLabels = Array(20).fill('');

    // DOM Elements
    const statusBadge = document.getElementById('status-badge');
    const statusText = document.getElementById('status-text');
    const simBanner = document.getElementById('simulation-banner');
    
    const statTotal = document.getElementById('stat-total');
    const statPps = document.getElementById('stat-pps');
    const statTcp = document.getElementById('stat-tcp');
    const statTcpPct = document.getElementById('stat-tcp-pct');
    const statUdp = document.getElementById('stat-udp');
    const statUdpPct = document.getElementById('stat-udp-pct');
    const statIcmp = document.getElementById('stat-icmp');
    const statIcmpPct = document.getElementById('stat-icmp-pct');
    
    const activeModeLabel = document.getElementById('active-mode-label');
    const bufferSizeLabel = document.getElementById('buffer-size-label');
    
    const btnStart = document.getElementById('btn-start');
    const btnStop = document.getElementById('btn-stop');
    const btnClear = document.getElementById('btn-clear');
    
    const filterProtocol = document.getElementById('filter-protocol');
    const filterThreat = document.getElementById('filter-threat');
    const tableBody = document.getElementById('packet-table-body');
    const sysInterface = document.getElementById('sys-interface');

    /* ==========================================================================
       CHART CONFIGURATIONS
       ========================================================================== */
    
    function initCharts() {
        // 1. Protocol Pie Chart
        const ctxProto = document.getElementById('chart-protocol').getContext('2d');
        protocolChart = new Chart(ctxProto, {
            type: 'doughnut',
            data: {
                labels: ['TCP', 'UDP', 'ICMP', 'Other'],
                datasets: [{
                    data: [0, 0, 0, 0],
                    backgroundColor: [
                        'rgba(59, 130, 246, 0.75)', // TCP - Blue
                        'rgba(16, 185, 129, 0.75)', // UDP - Green
                        'rgba(168, 85, 247, 0.75)', // ICMP - Purple
                        'rgba(142, 155, 180, 0.6)'  // Other - Gray
                    ],
                    borderColor: [
                        '#3b82f6',
                        '#10b981',
                        '#a855f7',
                        '#8e9bb4'
                    ],
                    borderWidth: 1.5,
                    hoverOffset: 4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: {
                        position: 'right',
                        labels: {
                            color: '#8e9bb4',
                            font: { family: 'Outfit', size: 12 }
                        }
                    }
                },
                cutout: '70%'
            }
        });

        // 2. Traffic Volume Bar Chart (Line representation for density)
        const ctxVol = document.getElementById('chart-volume').getContext('2d');
        const gradient = ctxVol.createLinearGradient(0, 0, 0, 200);
        gradient.addColorStop(0, 'rgba(0, 229, 255, 0.4)');
        gradient.addColorStop(1, 'rgba(0, 229, 255, 0.01)');

        volumeChart = new Chart(ctxVol, {
            type: 'line',
            data: {
                labels: trafficLabels,
                datasets: [{
                    label: 'Packets Received',
                    data: trafficHistory,
                    fill: true,
                    backgroundColor: gradient,
                    borderColor: '#00e5ff',
                    borderWidth: 2,
                    tension: 0.3,
                    pointBackgroundColor: '#00e5ff',
                    pointBorderColor: '#fff',
                    pointRadius: 2,
                    pointHoverRadius: 5
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    legend: { display: false }
                },
                scales: {
                    x: {
                        grid: { color: 'rgba(255, 255, 255, 0.03)' },
                        ticks: { color: '#8e9bb4', font: { family: 'Fira Code', size: 9 } }
                    },
                    y: {
                        grid: { color: 'rgba(255, 255, 255, 0.03)' },
                        ticks: { color: '#8e9bb4', font: { family: 'Fira Code', size: 10 } },
                        beginAtZero: true
                    }
                }
            }
        });
    }

    /* ==========================================================================
       API INTERACTIONS
       ========================================================================== */

    async function checkStatus() {
        try {
            const response = await fetch('/api/status');
            const data = await response.json();
            
            updateStatusUI(data);
            updateStatsUI(data.stats);
            
            if (data.is_running) {
                if (!pollIntervalId) {
                    startPolling();
                }
            } else {
                if (pollIntervalId) {
                    stopPolling();
                }
            }
        } catch (error) {
            console.error("Status fetch failed:", error);
        }
    }

    async function startCapture() {
        try {
            const response = await fetch('/api/start', { method: 'POST' });
            const data = await response.json();
            
            if (data.success) {
                updateStatusUI(data.status);
                startPolling();
            }
        } catch (error) {
            console.error("Failed to start capture:", error);
        }
    }

    async function stopCapture() {
        try {
            const response = await fetch('/api/stop', { method: 'POST' });
            const data = await response.json();
            
            if (data.success) {
                updateStatusUI(data.status);
                stopPolling();
            }
        } catch (error) {
            console.error("Failed to stop capture:", error);
        }
    }

    async function clearLogs() {
        try {
            const response = await fetch('/api/clear', { method: 'POST' });
            const data = await response.json();
            
            if (data.success) {
                // Clear UI cache
                lastPacketId = 0;
                packetsBuffer = [];
                
                // Reset Charts
                trafficHistory.fill(0);
                trafficLabels.fill('');
                volumeChart.update();
                
                protocolChart.data.datasets[0].data = [0, 0, 0, 0];
                protocolChart.update();
                
                // Clear Table
                tableBody.innerHTML = `
                    <tr class="table-placeholder">
                        <td colspan="8" class="text-center py-4 text-muted font-mono">
                            <i class="fa-solid fa-shield-halved fa-beat-fade mb-2 fs-4 text-cyan"></i>
                            <p class="mb-0 small">LOGS CLEARED // RUN CAPTURE TO VIEW FRESH STREAMS</p>
                        </td>
                    </tr>
                `;
                
                // Refresh Status & Stats
                checkStatus();
            }
        } catch (error) {
            console.error("Failed to clear logs:", error);
        }
    }

    async function fetchPacketsDelta() {
        try {
            const now = Date.now();
            const timeDeltaSec = (now - lastPollTime) / 1000;
            lastPollTime = now;
            
            const response = await fetch(`/api/packets?since_id=${lastPacketId}&limit=200`);
            const data = await response.json();
            
            if (data.count > 0) {
                // Determine max packet ID in the batch
                const latestId = Math.max(...data.packets.map(p => p.id));
                lastPacketId = latestId;
                
                // Prepend new packets to local buffer
                packetsBuffer = [...data.packets, ...packetsBuffer].slice(0, maxBufferSize);
                
                // Update table with filtered subset
                renderTable();
                
                // Update volume history charts
                updateTrafficVolumeChart(data.count, timeDeltaSec);
            } else {
                updateTrafficVolumeChart(0, timeDeltaSec);
            }
        } catch (error) {
            console.error("Failed to fetch packet deltas:", error);
        }
    }

    /* ==========================================================================
       UI UPDATES
       ========================================================================== */

    function updateStatusUI(status) {
        isRunning = status.is_running;
        
        // Status Badge Styling
        if (isRunning) {
            statusBadge.className = 'status-badge running';
            statusText.innerText = 'ACTIVE';
            
            btnStart.disabled = true;
            btnStop.disabled = false;
        } else {
            statusBadge.className = 'status-badge stopped';
            statusText.innerText = 'INACTIVE';
            
            btnStart.disabled = false;
            btnStop.disabled = true;
        }
        
        // Mode Banner Visibility
        if (isRunning && status.mode === 'simulated') {
            simBanner.classList.remove('d-none');
            activeModeLabel.innerText = "Mode: SIMULATED (Fallback)";
            activeModeLabel.className = "small text-amber font-mono";
            sysInterface.innerText = "Simulated Loopback";
        } else if (isRunning && status.mode === 'live') {
            simBanner.classList.add('d-none');
            activeModeLabel.innerText = "Mode: LIVE CAPTURE";
            activeModeLabel.className = "small text-green font-mono";
            sysInterface.innerText = "Ethernet/Wi-Fi (Promiscuous)";
        } else {
            simBanner.classList.add('d-none');
            activeModeLabel.innerText = "Mode: IDLE";
            activeModeLabel.className = "small text-muted font-mono";
        }
    }

    function updateStatsUI(stats) {
        if (!stats) return;
        
        // Total count
        statTotal.innerText = stats.total.toLocaleString();
        bufferSizeLabel.innerText = `Buffer: ${packetsBuffer.length}/1000`;
        
        // Protocol specific counts
        statTcp.innerText = stats.tcp.toLocaleString();
        statUdp.innerText = stats.udp.toLocaleString();
        statIcmp.innerText = stats.icmp.toLocaleString();
        
        // Compute Percentages
        const total = stats.total || 1; // avoid division by zero
        statTcpPct.innerText = Math.round((stats.tcp / total) * 100) + '%';
        statUdpPct.innerText = Math.round((stats.udp / total) * 100) + '%';
        statIcmpPct.innerText = Math.round((stats.icmp / total) * 100) + '%';
        
        // Update Doughnut Chart values
        if (protocolChart) {
            protocolChart.data.datasets[0].data = [stats.tcp, stats.udp, stats.icmp, stats.other];
            protocolChart.update();
        }
    }

    function updateTrafficVolumeChart(newPacketsCount, timeDeltaSec) {
        if (!volumeChart) return;
        
        // Calculate Packets Per Second (PPS)
        const pps = Math.round(newPacketsCount / (timeDeltaSec || 1.5));
        statPps.innerText = `${pps} pps`;
        
        // Update array history
        trafficHistory.push(newPacketsCount);
        trafficHistory.shift();
        
        const timestamp = new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit', second: '2-digit' });
        trafficLabels.push(timestamp);
        trafficLabels.shift();
        
        volumeChart.update();
    }

    function renderTable() {
        // Filter based on select values
        const protoFilter = filterProtocol.value;
        const threatFilter = filterThreat.value;
        
        let filteredPackets = packetsBuffer;
        
        if (protoFilter !== 'ALL') {
            filteredPackets = filteredPackets.filter(p => p.proto === protoFilter);
        }
        
        if (threatFilter !== 'ALL') {
            filteredPackets = filteredPackets.filter(p => p.status === threatFilter);
        }
        
        if (filteredPackets.length === 0) {
            tableBody.innerHTML = `
                <tr class="table-placeholder">
                    <td colspan="8" class="text-center py-4 text-muted font-mono">
                        <i class="fa-solid fa-filter mb-2 fs-5 text-muted"></i>
                        <p class="mb-0 small">NO PACKETS MATCHING ACTIVE FILTERS</p>
                    </td>
                </tr>
            `;
            return;
        }
        
        // Render rows
        let htmlRows = '';
        filteredPackets.forEach(p => {
            // Row classes based on threat flag
            let rowClass = '';
            if (p.status === 'Suspicious') {
                rowClass = 'row-suspicious';
            } else if (p.status === 'Warning') {
                rowClass = 'row-warning';
            }
            
            // Protocol badges classes
            let protoClass = 'proto-other';
            if (p.proto === 'TCP') protoClass = 'proto-tcp';
            else if (p.proto === 'UDP') protoClass = 'proto-udp';
            else if (p.proto === 'ICMP') protoClass = 'proto-icmp';
            
            // Threat status labels
            let threatClass = 'normal';
            let threatIcon = 'fa-circle-check';
            if (p.status === 'Warning') {
                threatClass = 'warning';
                threatIcon = 'fa-triangle-exclamation';
            } else if (p.status === 'Suspicious') {
                threatClass = 'suspicious';
                threatIcon = 'fa-shield-halved';
            }
            
            htmlRows += `
                <tr class="${rowClass} fade-in">
                    <td class="font-mono text-cyan fw-bold">${p.id}</td>
                    <td class="font-mono text-muted">${p.timestamp}</td>
                    <td class="font-mono text-light">${p.src}:${p.sport || '*'}</td>
                    <td class="font-mono text-light">${p.dst}:${p.dport || '*'}</td>
                    <td><span class="badge-cyber ${protoClass}">${p.proto}</span></td>
                    <td class="font-mono">${p.size}</td>
                    <td class="font-mono text-truncate text-muted" style="max-width: 250px;" title="${p.info}">${p.info}</td>
                    <td>
                        <span class="status-pill ${threatClass}">
                            <i class="fa-solid ${threatIcon} me-1"></i>${p.status}
                        </span>
                    </td>
                </tr>
            `;
        });
        
        tableBody.innerHTML = htmlRows;
    }

    /* ==========================================================================
       POLLING CONTROLLERS
       ========================================================================== */
       
    function startPolling() {
        if (pollIntervalId) return;
        
        // Poll status immediately, then start loop
        fetchPacketsDelta();
        pollIntervalId = setInterval(() => {
            checkStatus();
            fetchPacketsDelta();
        }, 1500); // 1.5 seconds polling rate
        
        console.log("[FOREGROUND] Polling thread initiated.");
    }
    
    function stopPolling() {
        if (!pollIntervalId) return;
        
        clearInterval(pollIntervalId);
        pollIntervalId = null;
        console.log("[FOREGROUND] Polling thread deactivated.");
    }

    /* ==========================================================================
       EVENT LISTENERS
       ========================================================================== */

    btnStart.addEventListener('click', startCapture);
    btnStop.addEventListener('click', stopCapture);
    btnClear.addEventListener('click', clearLogs);
    
    filterProtocol.addEventListener('change', renderTable);
    filterThreat.addEventListener('change', renderTable);

    // Sidebar navigation click simulator
    const navItems = document.querySelectorAll('.nav-item');
    navItems.forEach(item => {
        item.addEventListener('click', (e) => {
            navItems.forEach(i => i.classList.remove('active'));
            item.classList.add('active');
        });
    });

    /* ==========================================================================
       INITIALIZATION
       ========================================================================== */

    initCharts();
    checkStatus(); // Initial sync of state and charts
});
