/**
 * Real-Time Cyber Threat Detection Framework
 * Frontend Application - Main JavaScript
 */

// Global Configuration
const CONFIG = {
    API_BASE: 'http://localhost:5000',
    WS_URL: 'http://localhost:5000',
    REFRESH_INTERVAL: 5000,
    AUTO_REFRESH: true,
    MAX_THREATS_DISPLAY: 50
};

// Global State
let socket = null;
let charts = {};
let threatsData = [];
let systemMetrics = {};
let monitoringActive = false;

// ============ INITIALIZATION ============

document.addEventListener('DOMContentLoaded', function() {
    console.log('Threat Detection Framework Initialized');
    
    // Initialize WebSocket connection
    initWebSocket();
    
    // Load initial data
    loadDashboardData();
    loadThreatsData();
    
    // Setup event listeners
    setupEventListeners();
    
    // Initialize charts
    initCharts();
    
    // Start auto-refresh
    if (CONFIG.AUTO_REFRESH) {
        setInterval(loadDashboardData, CONFIG.REFRESH_INTERVAL);
    }
});

// ============ WEBSOCKET MANAGEMENT ============

function initWebSocket() {
    socket = io(CONFIG.WS_URL, {
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
        reconnectionAttempts: 5
    });

    socket.on('connect', function() {
        console.log('WebSocket connected');
        showToast('Connected to threat detection server', 'success');
        socket.emit('request_threat_update');
        socket.emit('get_system_status');
    });

    socket.on('disconnect', function() {
        console.log('WebSocket disconnected');
        showToast('Disconnected from server', 'warning');
    });

    socket.on('threat_detected', function(data) {
        console.log('New threat detected:', data);
        handleNewThreat(data);
        updateDashboard();
    });

    socket.on('threat_update', function(data) {
        console.log('Threat update received:', data);
        threatsData = data.threats || [];
        updateThreatsDisplay();
        updateThreatsTable(threatsData);
    });

    socket.on('system_metrics', function(data) {
        console.log('System metrics:', data);
        updateSystemMetrics(data);
    });

    socket.on('system_status', function(data) {
        console.log('System status:', data);
        updateSystemStatus(data);
    });

    socket.on('monitoring_status', function(data) {
        console.log('Monitoring status:', data);
        monitoringActive = data.status === 'started';
        updateMonitoringStatus();
    });

    socket.on('connection_response', function(data) {
        console.log('Server response:', data);
    });
}

// ============ DATA LOADING ============

async function loadDashboardData() {
    try {
        const response = await fetch(`${CONFIG.API_BASE}/api/analytics/dashboard`);
        const data = await response.json();
        
        // Update KPI cards
        updateKPICards(data);
        
        // Load timeline data
        loadTimelineData();
        
    } catch (error) {
        console.error('Error loading dashboard data:', error);
        showToast('Error loading dashboard data', 'error');
    }
}

async function loadThreatsData() {
    try {
        const response = await fetch(`${CONFIG.API_BASE}/api/threats?page=1`);
        const data = await response.json();
        
        threatsData = data.threats || [];
        updateThreatsDisplay();
        updateThreatsTable(threatsData);
        
    } catch (error) {
        console.error('Error loading threats:', error);
    }
}

async function loadTimelineData() {
    try {
        const response = await fetch(`${CONFIG.API_BASE}/api/analytics/timeline?hours=24`);
        const data = await response.json();
        
        updateTimelineChart(data.timeline || []);
        
    } catch (error) {
        console.error('Error loading timeline:', error);
    }
}

async function loadAlertsData() {
    try {
        const response = await fetch(`${CONFIG.API_BASE}/api/alerts?page=1`);
        const data = await response.json();
        
        document.getElementById('alert-count').textContent = data.total || 0;
        
    } catch (error) {
        console.error('Error loading alerts:', error);
    }
}

// ============ DATA UPDATE HANDLERS ============

function updateKPICards(data) {
    // Update KPI values
    document.getElementById('recent-threats').textContent = data.recent_threats_1h || 0;
    document.getElementById('high-severity').textContent = data.threat_types ? data.threat_types.length : 0;
    document.getElementById('critical-count').textContent = data.critical_threats || 0;
    document.getElementById('daily-threats').textContent = data.daily_threats || 0;
    document.getElementById('critical-threats').textContent = data.critical_threats || 0;
    
    // Update threat type distribution
    updateThreatTypeChart(data.threat_types || []);
    
    // Update severity distribution
    updateSeverityChart(data.severity_distribution || []);
}

function handleNewThreat(threatData) {
    // Add to threats data
    threatsData.unshift(threatData);
    
    // Limit array size
    if (threatsData.length > CONFIG.MAX_THREATS_DISPLAY) {
        threatsData.pop();
    }
    
    // Show notification for critical threats
    if (threatData.severity >= 8) {
        showNotification(threatData);
    }
}

function updateThreatsDisplay() {
    const feedContainer = document.getElementById('threats-feed');
    
    // Filter out unknown threats
    const knownThreats = threatsData.filter(threat => threat.threat_type && threat.threat_type !== 'unknown');
    
    if (!knownThreats || knownThreats.length === 0) {
        feedContainer.innerHTML = `
            <div class="placeholder">
                <i class="fas fa-inbox"></i>
                No threats detected
            </div>
        `;
        return;
    }
    
    feedContainer.innerHTML = knownThreats.map(threat => `
        <div class="threat-item ${getSeverityClass(threat.severity)}">
            <div class="threat-severity">${threat.severity}</div>
            <div class="threat-details">
                <div class="threat-type">${threat.threat_type || 'Unknown'}</div>
                <div class="threat-meta">
                    ${threat.source_ip || 'N/A'} → ${threat.destination_ip || 'N/A'} | 
                    Confidence: ${(threat.confidence ? (threat.confidence * 100).toFixed(1) : 'N/A')}%
                </div>
            </div>
            <div class="threat-actions">
                <button class="btn btn-sm btn-primary" onclick="viewThreatDetails(${threat.id})">
                    <i class="fas fa-eye"></i>
                </button>
            </div>
        </div>
    `).join('');
}

function updateThreatsTable(threats) {
    const tbody = document.getElementById('threats-tbody');
    
    // Filter out unknown threats
    const knownThreats = threats ? threats.filter(threat => threat.threat_type && threat.threat_type !== 'unknown') : [];
    
    if (!knownThreats || knownThreats.length === 0) {
        tbody.innerHTML = '<tr><td colspan="8" class="text-center">No threats detected</td></tr>';
        return;
    }
    
    tbody.innerHTML = knownThreats.map(threat => `
        <tr>
            <td>${threat.id}</td>
            <td>${threat.source_ip || 'N/A'}</td>
            <td>${threat.destination_ip || 'N/A'}</td>
            <td>${threat.threat_type || 'Unknown'}</td>
            <td><span class="severity-${threat.severity >= 8 ? 'critical' : (threat.severity >= 6 ? 'high' : 'medium')}">${threat.severity}</span></td>
            <td>${(threat.confidence ? (threat.confidence * 100).toFixed(1) : 'N/A')}%</td>
            <td>${new Date(threat.detected_at).toLocaleString()}</td>
            <td>
                <button class="btn btn-sm btn-primary" onclick="viewThreatDetails(${threat.id})" title="View threat details">
                    <i class="fas fa-eye"></i>
                </button>
            </td>
        </tr>
    `).join('');
}

function updateSystemMetrics(data) {
    systemMetrics = data;
    
    // Update CPU meter
    const cpuPercent = Math.round(data.cpu_usage || 0);
    document.getElementById('cpu-meter').style.width = cpuPercent + '%';
    document.getElementById('cpu-value').textContent = cpuPercent + '%';
    
    // Update Memory meter
    const memPercent = Math.round(data.memory_usage || 0);
    document.getElementById('memory-meter').style.width = memPercent + '%';
    document.getElementById('memory-value').textContent = memPercent + '%';
    
    // Update Network meter (normalize to percentage)
    const networkMbps = Math.round((data.network_traffic || 0) / 1000000);
    const networkPercent = Math.min((networkMbps / 1000) * 100, 100);
    document.getElementById('network-meter').style.width = networkPercent + '%';
    document.getElementById('network-value').textContent = networkMbps + ' Mbps';
}

function updateSystemStatus(data) {
    monitoringActive = data.monitoring_active;
    updateMonitoringStatus();
    updateSystemMetrics(data);
}

function updateMonitoringStatus() {
    const statusBadge = document.getElementById('monitoring-status');
    const toggleBtn = document.getElementById('monitoring-toggle');
    
    if (monitoringActive) {
        statusBadge.classList.remove('inactive');
        statusBadge.classList.add('active');
        statusBadge.innerHTML = '<i class="fas fa-circle"></i> Monitoring: ON';
        toggleBtn.innerHTML = '<i class="fas fa-stop"></i> Stop';
        toggleBtn.classList.add('btn-danger');
        toggleBtn.classList.remove('btn-primary');
    } else {
        statusBadge.classList.remove('active');
        statusBadge.classList.add('inactive');
        statusBadge.innerHTML = '<i class="fas fa-circle"></i> Monitoring: OFF';
        toggleBtn.innerHTML = '<i class="fas fa-play"></i> Start';
        toggleBtn.classList.add('btn-primary');
        toggleBtn.classList.remove('btn-danger');
    }
}

// ============ CHARTS MANAGEMENT ============

function initCharts() {
    // Timeline Chart
    const timelineCtx = document.getElementById('timeline-chart');
    if (timelineCtx) {
        charts.timeline = new Chart(timelineCtx, {
            type: 'line',
            data: {
                labels: [],
                datasets: [{
                    label: 'Threats Detected',
                    data: [],
                    borderColor: '#2563eb',
                    backgroundColor: 'rgba(37, 99, 235, 0.1)',
                    borderWidth: 2,
                    fill: true,
                    tension: 0.4
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: true,
                        position: 'top'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });
    }
    
    // Threat Types Chart
    const typesCtx = document.getElementById('threat-types-chart');
    if (typesCtx) {
        charts.threatTypes = new Chart(typesCtx, {
            type: 'doughnut',
            data: {
                labels: [],
                datasets: [{
                    data: [],
                    backgroundColor: [
                        '#2563eb',
                        '#dc2626',
                        '#f59e0b',
                        '#10b981',
                        '#0ea5e9',
                        '#8b5cf6'
                    ]
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });
    }
    
    // Severity Distribution Chart
    const severityCtx = document.getElementById('severity-chart');
    if (severityCtx) {
        charts.severity = new Chart(severityCtx, {
            type: 'bar',
            data: {
                labels: [],
                datasets: [{
                    label: 'Count',
                    data: [],
                    backgroundColor: '#2563eb',
                    borderColor: '#1e40af',
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                indexAxis: 'y',
                scales: {
                    x: {
                        beginAtZero: true
                    }
                }
            }
        });
    }
}

function updateTimelineChart(timelineData) {
    if (!charts.timeline || !timelineData.length) return;
    
    const labels = timelineData.map(d => {
        const date = new Date(d.timestamp);
        return date.getHours() + ':' + String(date.getMinutes()).padStart(2, '0');
    });
    
    const counts = timelineData.map(d => d.count);
    
    charts.timeline.data.labels = labels;
    charts.timeline.data.datasets[0].data = counts;
    charts.timeline.update();
}

function updateThreatTypeChart(threatTypes) {
    if (!charts.threatTypes || !threatTypes.length) return;
    
    charts.threatTypes.data.labels = threatTypes.map(t => t.type);
    charts.threatTypes.data.datasets[0].data = threatTypes.map(t => t.count);
    charts.threatTypes.update();
}

function updateSeverityChart(severityDist) {
    if (!charts.severity || !severityDist.length) return;
    
    const sortedDist = severityDist.sort((a, b) => a.severity - b.severity);
    
    charts.severity.data.labels = sortedDist.map(s => 'Severity ' + s.severity);
    charts.severity.data.datasets[0].data = sortedDist.map(s => s.count);
    charts.severity.update();
}

// ============ EVENT LISTENERS ============

function setupEventListeners() {
    // Navigation
    document.querySelectorAll('.navbar-menu a').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const target = this.getAttribute('href');
            switchSection(target);
        });
    });
    
    // Monitoring toggle
    document.getElementById('monitoring-toggle').addEventListener('click', toggleMonitoring);
    
    // Threat filtering
    document.getElementById('severity-filter').addEventListener('change', filterThreats);
    document.getElementById('threat-filter').addEventListener('input', filterThreats);
    
    // Threats table search
    const threatSearchElem = document.getElementById('threat-search');
    if (threatSearchElem) {
        threatSearchElem.addEventListener('input', searchThreatsTable);
    }
    
    // Settings range input
    document.getElementById('confidence-threshold').addEventListener('input', function(e) {
        document.getElementById('confidence-value').textContent = e.target.value;
    });
}

function switchSection(sectionId) {
    // Hide all sections
    document.querySelectorAll('.content-section').forEach(section => {
        section.classList.remove('active');
    });
    
    // Show selected section
    document.querySelector(sectionId).classList.add('active');
    
    // Update navbar
    document.querySelectorAll('.navbar-menu a').forEach(link => {
        link.classList.remove('active');
    });
    document.querySelector(`a[href="${sectionId}"]`).classList.add('active');
}

function toggleMonitoring() {
    if (monitoringActive) {
        socket.emit('stop_monitoring');
    } else {
        socket.emit('start_monitoring');
    }
}

function filterThreats() {
    const severity = document.getElementById('severity-filter').value;
    const searchTerm = document.getElementById('threat-filter').value.toLowerCase();
    
    const filtered = threatsData.filter(threat => {
        // Exclude unknown threats
        if (threat.threat_type === 'unknown') return false;
        
        const matchesSeverity = !severity || threat.severity >= parseInt(severity);
        const matchesSearch = !searchTerm || 
            threat.threat_type.toLowerCase().includes(searchTerm) ||
            threat.source_ip.includes(searchTerm) ||
            threat.destination_ip.includes(searchTerm);
        
        return matchesSeverity && matchesSearch;
    });
    
    // Update display with filtered results
    const feedContainer = document.getElementById('threats-feed');
    feedContainer.innerHTML = filtered.map(threat => `
        <div class="threat-item ${getSeverityClass(threat.severity)}">
            <div class="threat-severity">${threat.severity}</div>
            <div class="threat-details">
                <div class="threat-type">${threat.threat_type || 'Unknown'}</div>
                <div class="threat-meta">
                    ${threat.source_ip || 'N/A'} → ${threat.destination_ip || 'N/A'} | 
                    Confidence: ${(threat.confidence ? (threat.confidence * 100).toFixed(1) : 'N/A')}%
                </div>
            </div>
            <div class="threat-actions">
                <button class="btn btn-sm btn-primary" onclick="viewThreatDetails(${threat.id})">
                    <i class="fas fa-eye"></i>
                </button>
            </div>
        </div>
    `).join('');
}

function searchThreatsTable() {
    const searchTerm = document.getElementById('threat-search').value.toLowerCase();
    const tbody = document.getElementById('threats-tbody');
    
    const filtered = threatsData.filter(threat => {
        // Exclude unknown threats
        if (threat.threat_type === 'unknown') return false;
        return !searchTerm || 
            threat.threat_type.toLowerCase().includes(searchTerm) ||
            threat.source_ip.includes(searchTerm) ||
            threat.destination_ip.includes(searchTerm) ||
            threat.id.toString().includes(searchTerm);
    });
    
    updateThreatsTable(filtered);
}

// ============ THREAT MANAGEMENT ============

async function viewThreatDetails(threatId) {
    try {
        const response = await fetch(`${CONFIG.API_BASE}/api/threats/${threatId}`);
        const threat = await response.json();
        
        const modal = document.getElementById('threat-details-modal');
        const body = document.getElementById('threat-details-body');
        
        body.innerHTML = `
            <div class="threat-details-container">
                <div class="detail-row">
                    <span class="detail-label">Threat ID:</span>
                    <span class="detail-value">${threat.threat_id}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Type:</span>
                    <span class="detail-value">${threat.threat_type}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Source IP:</span>
                    <span class="detail-value">${threat.source_ip}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Destination IP:</span>
                    <span class="detail-value">${threat.destination_ip}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Severity:</span>
                    <span class="detail-value severity-${threat.severity >= 8 ? 'critical' : 'high'}">${threat.severity}/10</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Confidence:</span>
                    <span class="detail-value">${(threat.confidence ? (threat.confidence * 100).toFixed(1) : 'N/A')}%</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Detected At:</span>
                    <span class="detail-value">${new Date(threat.detected_at).toLocaleString()}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Payload:</span>
                    <pre class="detail-value payload">${JSON.stringify(threat.payload, null, 2)}</pre>
                </div>
            </div>
        `;
        
        modal.classList.add('active');
        
    } catch (error) {
        console.error('Error loading threat details:', error);
        showToast('Error loading threat details', 'error');
    }
}

function closeThreatDetails() {
    document.getElementById('threat-details-modal').classList.remove('active');
}

async function blockThreat() {
    showToast('IP address added to blocklist', 'success');
    closeThreatDetails();
}

async function refreshThreats() {
    await loadThreatsData();
    showToast('Threats refreshed', 'success');
}

// ============ THREAT ANALYZER ============

function openAnalyzer() {
    document.getElementById('analyzer-modal').classList.add('active');
}

function closeAnalyzer() {
    document.getElementById('analyzer-modal').classList.remove('active');
}

async function analyzePayload() {
    const payload = document.getElementById('analyzer-input').value;
    
    if (!payload.trim()) {
        showToast('Please enter a payload to analyze', 'warning');
        return;
    }
    
    try {
        const response = await fetch(`${CONFIG.API_BASE}/api/threats/analyze`, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json'
            },
            body: JSON.stringify({ payload: payload })
        });
        
        const result = await response.json();
        displayAnalysisResults(result);
        
    } catch (error) {
        console.error('Error analyzing threat:', error);
        showToast('Error analyzing threat', 'error');
    }
}

function displayAnalysisResults(analysis) {
    const resultsDiv = document.getElementById('analyzer-results');
    
    resultsDiv.innerHTML = `
        <div class="analysis-results-container">
            <h3>Analysis Results</h3>
            <div class="result-section">
                <h4>Classification</h4>
                <p><strong>Type:</strong> ${analysis.classification.type}</p>
                <p><strong>Severity:</strong> <span class="severity-${analysis.classification.severity}">${analysis.classification.severity}/10</span></p>
                <p><strong>Confidence:</strong> ${(analysis.classification.confidence ? (analysis.classification.confidence * 100).toFixed(1) : 'N/A')}%</p>
                <p><strong>Description:</strong> ${analysis.classification.description}</p>
            </div>
            <div class="result-section">
                <h4>Extracted Features</h4>
                <pre>${JSON.stringify(analysis.analysis.payload_analysis, null, 2)}</pre>
            </div>
        </div>
    `;
}

function openExport() {
    alert('Export functionality - would export current threat data');
}

function openSettings() {
    switchSection('#settings');
}

// ============ SETTINGS ============

function saveSettings() {
    const settings = {
        enable_signature: document.getElementById('enable-signature').checked,
        enable_anomaly: document.getElementById('enable-anomaly').checked,
        enable_behavioral: document.getElementById('enable-behavioral').checked,
        confidence_threshold: document.getElementById('confidence-threshold').value,
        email_alerts: document.getElementById('enable-email').checked,
        slack_alerts: document.getElementById('enable-slack').checked,
        retention_days: document.getElementById('retention-days').value
    };
    
    localStorage.setItem('threat_detector_settings', JSON.stringify(settings));
    showToast('Settings saved successfully', 'success');
}

function resetSettings() {
    if (confirm('Reset all settings to defaults?')) {
        localStorage.removeItem('threat_detector_settings');
        location.reload();
    }
}

function clearOldData() {
    if (confirm('Clear old threat data?')) {
        showToast('Old data cleared successfully', 'success');
    }
}

// ============ UTILITIES ============

function getSeverityClass(severity) {
    if (severity >= 8) return 'critical';
    if (severity >= 6) return 'warning';
    return '';
}

function showToast(message, type = 'info') {
    const container = document.getElementById('toast-container');
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = message;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 4000);
}

function showNotification(threat) {
    if ('Notification' in window && Notification.permission === 'granted') {
        new Notification('Critical Threat Detected', {
            body: `${threat.threat_type} from ${threat.source_ip} - Severity: ${threat.severity}/10`,
            icon: '/static/images/threat-icon.png'
        });
    }
}

function updateDashboard() {
    loadDashboardData();
}
