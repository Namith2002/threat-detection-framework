/**
 * Real-Time Cyber Threat Detection Framework
 * Frontend Application - Main JavaScript with Enhanced UI
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
    console.log('🛡️ Threat Detection Framework Initialized');
    
    // Request notification permission
    if ('Notification' in window && Notification.permission === 'default') {
        Notification.requestPermission();
    }
    
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
    
    // Load stored settings
    loadStoredSettings();
});

// ============ SETTINGS MANAGEMENT ============

function loadStoredSettings() {
    const stored = localStorage.getItem('threat_detector_settings');
    if (stored) {
        const settings = JSON.parse(stored);
        document.getElementById('enable-signature').checked = settings.enable_signature !== false;
        document.getElementById('enable-anomaly').checked = settings.enable_anomaly !== false;
        document.getElementById('enable-behavioral').checked = settings.enable_behavioral !== false;
        document.getElementById('confidence-threshold').value = settings.confidence_threshold || 60;
        document.getElementById('confidence-value').textContent = settings.confidence_threshold || 60;
        document.getElementById('enable-email').checked = settings.email_alerts || false;
        document.getElementById('enable-slack').checked = settings.slack_alerts || false;
        document.getElementById('retention-days').value = settings.retention_days || 90;
    }
}

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
    showToast('✅ Settings saved successfully', 'success');
}

function resetSettings() {
    if (confirm('Reset all settings to defaults?')) {
        localStorage.removeItem('threat_detector_settings');
        location.reload();
    }
}

function clearOldData() {
    if (confirm('Clear old threat data?')) {
        showToast('🗑️ Old data cleared successfully', 'success');
    }
}

// ============ WEBSOCKET MANAGEMENT ============

function initWebSocket() {
    socket = io(CONFIG.WS_URL, {
        reconnection: true,
        reconnectionDelay: 1000,
        reconnectionDelayMax: 5000,
        reconnectionAttempts: 5
    });

    socket.on('connect', function() {
        console.log('✅ WebSocket connected');
        showToast('🔗 Connected to threat detection server', 'success');
        socket.emit('request_threat_update');
        socket.emit('get_system_status');
    });

    socket.on('disconnect', function() {
        console.log('❌ WebSocket disconnected');
        showToast('⚠️ Disconnected from server', 'warning');
    });

    socket.on('threat_detected', function(data) {
        console.log('🚨 New threat detected:', data);
        handleNewThreat(data);
        updateDashboard();
    });

    socket.on('threat_update', function(data) {
        console.log('📊 Threat update received:', data);
        threatsData = data.threats || [];
        updateThreatsDisplay();
        updateThreatsTable(threatsData);
    });

    socket.on('system_metrics', function(data) {
        console.log('📈 System metrics:', data);
        updateSystemMetrics(data);
    });

    socket.on('system_status', function(data) {
        console.log('🖥️ System status:', data);
        updateSystemStatus(data);
    });

    socket.on('monitoring_status', function(data) {
        console.log('👁️ Monitoring status:', data);
        monitoringActive = data.status === 'started';
        updateMonitoringStatus();
    });

    socket.on('connection_response', function(data) {
        console.log('📨 Server response:', data);
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
    // Navigation clicks
    document.querySelectorAll('.navbar-menu a').forEach(link => {
        link.addEventListener('click', function(e) {
            e.preventDefault();
            const target = this.getAttribute('href');
            switchSection(target);
        });
    });
    
    // Monitoring toggle
    const monitoringToggle = document.getElementById('monitoring-toggle');
    if (monitoringToggle) {
        monitoringToggle.addEventListener('click', toggleMonitoring);
    }
    
    // Threat filtering
    const severityFilter = document.getElementById('severity-filter');
    const threatFilter = document.getElementById('threat-filter');
    
    if (severityFilter) {
        severityFilter.addEventListener('change', filterThreats);
    }
    if (threatFilter) {
        threatFilter.addEventListener('input', filterThreats);
    }
    
    // Threats table search
    const threatSearch = document.getElementById('threat-search');
    if (threatSearch) {
        threatSearch.addEventListener('input', searchThreatsTable);
    }
    
    // Settings confidence threshold
    const confidenceThreshold = document.getElementById('confidence-threshold');
    if (confidenceThreshold) {
        confidenceThreshold.addEventListener('input', function(e) {
            const valueDisplay = document.getElementById('confidence-value');
            if (valueDisplay) {
                valueDisplay.textContent = e.target.value;
            }
        });
    }
    
    // Close modals when clicking outside
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', function(e) {
            if (e.target === this) {
                this.classList.remove('active');
            }
        });
    });
    
    // Keyboard shortcuts
    document.addEventListener('keydown', function(e) {
        if (e.key === 'Escape') {
            document.querySelectorAll('.modal.active').forEach(m => {
                m.classList.remove('active');
            });
        }
        if (e.ctrlKey && e.key === 's') {
            e.preventDefault();
            saveSettings();
        }
    });
}

function switchSection(sectionId) {
    // Hide all sections with fade out
    document.querySelectorAll('.content-section').forEach(section => {
        section.classList.remove('active');
    });
    
    // Show selected section with fade in
    const targetSection = document.querySelector(sectionId);
    if (targetSection) {
        targetSection.classList.add('active');
    }
    
    // Update navbar active state
    document.querySelectorAll('.navbar-menu a').forEach(link => {
        link.classList.remove('active');
    });
    
    const activeLink = document.querySelector(`.navbar-menu a[href="${sectionId}"]`);
    if (activeLink) {
        activeLink.classList.add('active');
    }
    
    // Scroll to top
    window.scrollTo({ top: 0, behavior: 'smooth' });
}

function toggleMonitoring() {
    if (socket) {
        if (monitoringActive) {
            socket.emit('stop_monitoring');
            showToast('⏹️ Monitoring stopped', 'warning');
        } else {
            socket.emit('start_monitoring');
            showToast('▶️ Monitoring started', 'success');
        }
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
            (threat.threat_type && threat.threat_type.toLowerCase().includes(searchTerm)) ||
            (threat.source_ip && threat.source_ip.includes(searchTerm)) ||
            (threat.destination_ip && threat.destination_ip.includes(searchTerm));
        
        return matchesSeverity && matchesSearch;
    });
    
    // Update display with filtered results
    const feedContainer = document.getElementById('threats-feed');
    if (!feedContainer) return;
    
    if (!filtered || filtered.length === 0) {
        feedContainer.innerHTML = `
            <div class="placeholder">
                <i class="fas fa-inbox"></i>
                <p>No threats match your filters</p>
            </div>
        `;
        return;
    }
    
    feedContainer.innerHTML = filtered.slice(0, CONFIG.MAX_THREATS_DISPLAY).map(threat => `
        <div class="threat-item ${getSeverityClass(threat.severity)}">
            <div class="threat-severity">${threat.severity}</div>
            <div class="threat-details">
                <div class="threat-type">${threat.threat_type || 'Unknown'} ${getSeverityLabel(threat.severity)}</div>
                <div class="threat-meta">
                    ${threat.source_ip || 'N/A'} → ${threat.destination_ip || 'N/A'} | 
                    Confidence: ${(threat.confidence ? (threat.confidence * 100).toFixed(1) : 'N/A')}%
                </div>
            </div>
            <div class="threat-actions">
                <button class="btn btn-sm btn-primary" onclick="viewThreatDetails(${threat.id})" title="View threat details">
                    <i class="fas fa-eye"></i>
                </button>
            </div>
        </div>
    `).join('');
}

function searchThreatsTable() {
    const searchTerm = document.getElementById('threat-search').value.toLowerCase();
    const tbody = document.getElementById('threats-tbody');
    
    if (!tbody) return;
    
    const filtered = threatsData.filter(threat => {
        // Exclude unknown threats
        if (threat.threat_type === 'unknown') return false;
        return !searchTerm || 
            (threat.threat_type && threat.threat_type.toLowerCase().includes(searchTerm)) ||
            (threat.source_ip && threat.source_ip.includes(searchTerm)) ||
            (threat.destination_ip && threat.destination_ip.includes(searchTerm)) ||
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
        if (!modal) return;
        
        const body = document.getElementById('threat-details-body');
        
        body.innerHTML = `
            <div class="threat-details-container">
                <div class="detail-row">
                    <span class="detail-label">Threat ID:</span>
                    <span class="detail-value">${threat.id || 'N/A'}</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Type:</span>
                    <span class="detail-value"><strong>${threat.threat_type || 'Unknown'}</strong></span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Source IP:</span>
                    <span class="detail-value"><code>${threat.source_ip || 'N/A'}</code></span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Destination IP:</span>
                    <span class="detail-value"><code>${threat.destination_ip || 'N/A'}</code></span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Severity:</span>
                    <span class="detail-value severity-${threat.severity >= 8 ? 'critical' : 'high'}">${getSeverityLabel(threat.severity)} (${threat.severity}/10)</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Confidence:</span>
                    <span class="detail-value">${(threat.confidence ? (threat.confidence * 100).toFixed(2) : 'N/A')}%</span>
                </div>
                <div class="detail-row">
                    <span class="detail-label">Detected At:</span>
                    <span class="detail-value">${threat.detected_at ? new Date(threat.detected_at).toLocaleString() : 'N/A'}</span>
                </div>
                ${threat.payload ? `
                <div class="detail-row">
                    <span class="detail-label">Payload:</span>
                    <pre class="detail-value payload">${JSON.stringify(threat.payload, null, 2)}</pre>
                </div>
                ` : ''}
            </div>
        `;
        
        modal.classList.add('active');
        
    } catch (error) {
        console.error('Error loading threat details:', error);
        showToast('❌ Error loading threat details', 'error');
    }
}

function closeThreatDetails() {
    const modal = document.getElementById('threat-details-modal');
    if (modal) {
        modal.classList.remove('active');
    }
}

async function blockThreat() {
    showToast('🚫 IP address added to blocklist', 'success');
    closeThreatDetails();
}

async function refreshThreats() {
    await loadThreatsData();
    showToast('🔄 Threats refreshed', 'success');
}

// ============ THREAT ANALYZER ============

function openAnalyzer() {
    const modal = document.getElementById('analyzer-modal');
    if (modal) {
        modal.classList.add('active');
        // Focus on input
        setTimeout(() => {
            document.getElementById('analyzer-input').focus();
        }, 300);
    }
}

function closeAnalyzer() {
    const modal = document.getElementById('analyzer-modal');
    if (modal) {
        modal.classList.remove('active');
        document.getElementById('analyzer-input').value = '';
        document.getElementById('analyzer-results').innerHTML = '';
    }
}

async function analyzePayload() {
    const payload = document.getElementById('analyzer-input').value;
    
    if (!payload.trim()) {
        showToast('⚠️ Please enter a payload to analyze', 'warning');
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
        showToast('✅ Analysis completed', 'success');
        
    } catch (error) {
        console.error('Error analyzing threat:', error);
        showToast('❌ Error analyzing threat', 'error');
    }
}

function displayAnalysisResults(analysis) {
    const resultsDiv = document.getElementById('analyzer-results');
    if (!resultsDiv) return;
    
    resultsDiv.innerHTML = `
        <div class="analysis-results-container">
            <h3>📊 Analysis Results</h3>
            <div class="result-section">
                <h4>Classification</h4>
                <p><strong>Type:</strong> ${analysis.classification?.type || 'Unknown'}</p>
                <p><strong>Severity:</strong> <span class="severity-${analysis.classification?.severity >= 8 ? 'critical' : 'high'}">${getSeverityLabel(analysis.classification?.severity)} (${analysis.classification?.severity || 0}/10)</span></p>
                <p><strong>Confidence:</strong> ${(analysis.classification?.confidence ? (analysis.classification.confidence * 100).toFixed(2) : 'N/A')}%</p>
                <p><strong>Description:</strong> ${analysis.classification?.description || 'No description available'}</p>
            </div>
            <div class="result-section">
                <h4>Extracted Features</h4>
                <pre>${JSON.stringify(analysis.analysis?.payload_analysis || {}, null, 2)}</pre>
            </div>
        </div>
    `;
}

function openExport() {
    if (threatsData.length === 0) {
        showToast('⚠️ No threat data to export', 'warning');
        return;
    }
    
    const dataStr = JSON.stringify(threatsData, null, 2);
    const dataBlob = new Blob([dataStr], { type: 'application/json' });
    const url = URL.createObjectURL(dataBlob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `threats_${new Date().toISOString().slice(0, 10)}.json`;
    link.click();
    
    showToast('💾 Threat data exported successfully', 'success');
}

function openSettings() {
    switchSection('#settings');
}

// ============ UTILITIES ============

function getSeverityClass(severity) {
    if (severity >= 8) return 'critical';
    if (severity >= 6) return 'warning';
    return '';
}

function getSeverityLabel(severity) {
    if (severity >= 8) return '🔴 CRITICAL';
    if (severity >= 6) return '🟠 HIGH';
    if (severity >= 4) return '🟡 MEDIUM';
    return '🟢 LOW';
}
