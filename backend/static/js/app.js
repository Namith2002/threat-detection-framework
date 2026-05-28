/**
 * Threat Detection Framework - Main Application JavaScript
 */

// ===== Global State =====
let currentUser = null;
let socket = null;
let chartsMap = {};
let currentTheme = localStorage.getItem('theme') || 'light';

// ===== Socket.IO Connection =====
function initializeSocket() {
    socket = io();
    
    socket.on('connect', () => {
        console.log('Connected to server');
        showNotification('Connected to real-time updates', 'success', 'info');
    });
    
    socket.on('disconnect', () => {
        console.log('Disconnected from server');
        showNotification('Disconnected from server', 'warning', 'warning');
    });
    
    socket.on('threat_detected', (data) => {
        updateThreatData(data);
        showNotification(`New threat detected: ${data.threat_type}`, 'critical', 'danger');
        updateDashboard();
    });
    
    socket.on('metrics_update', (metrics) => {
        updateSystemMetrics(metrics);
    });
    
    socket.on('alert_triggered', (alert) => {
        showNotification(alert.message, alert.severity, 'warning');
        addAlertToList(alert);
    });
    
    socket.on('monitoring_status', (status) => {
        updateMonitoringStatus(status);
    });
}

// ===== Authentication =====
function login() {
    const username = document.getElementById('username')?.value;
    const password = document.getElementById('password')?.value;
    
    if (!username || !password) {
        showNotification('Please fill in all fields', 'warning', 'warning');
        return;
    }
    
    fetch('/api/auth/login', {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username, password })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            localStorage.setItem('token', data.token);
            localStorage.setItem('user', JSON.stringify(data.user));
            currentUser = data.user;
            window.location.href = '/dashboard';
        } else {
            showNotification(data.message || 'Login failed', 'error', 'danger');
        }
    })
    .catch(error => {
        console.error('Login error:', error);
        showNotification('An error occurred during login', 'error', 'danger');
    });
}

function logout() {
    localStorage.removeItem('token');
    localStorage.removeItem('user');
    window.location.href = '/login';
}

function isAuthenticated() {
    return !!localStorage.getItem('token');
}

function getAuthHeaders() {
    return {
        'Authorization': `Bearer ${localStorage.getItem('token')}`,
        'Content-Type': 'application/json'
    };
}

// ===== Navigation =====
function switchTab(tabName) {
    // Hide all sections
    document.querySelectorAll('.content-section').forEach(section => {
        section.classList.remove('active');
    });
    
    // Remove active from all nav links
    document.querySelectorAll('.navbar-menu a').forEach(link => {
        link.classList.remove('active');
    });
    
    // Show selected section
    const section = document.getElementById(tabName);
    if (section) {
        section.classList.add('active');
    }
    
    // Mark nav link as active
    if (window.event && window.event.target) {
        window.event.target.classList.add('active');
    } else if (event && event.target) {
        event.target.classList.add('active');
    }
    
    // Trigger tab-specific loads
    if (tabName === 'map') {
        setTimeout(initMap, 100);
    } else if (tabName === 'reports') {
        loadReports();
    } else if (tabName === 'analytics') {
        updateAnalyticsTab();
    }
}

// ===== Dashboard Functions =====
function updateDashboard() {
    updateThreatStats();
    updateSystemMetrics();
    loadRecentThreats();
    updateCharts();
}

function updateThreatStats() {
    fetch('/api/threats/stats', {
        headers: getAuthHeaders()
    })
    .then(response => response.json())
    .then(data => {
        document.getElementById('daily-threats').textContent = data.daily_count || 0;
        document.getElementById('critical-threats').textContent = data.critical_count || 0;
        document.getElementById('alert-count').textContent = data.alert_count || 0;
        
        // Update new stats
        if (document.getElementById('total-threats')) document.getElementById('total-threats').textContent = data.total_threats || 0;
        if (document.getElementById('avg-severity')) document.getElementById('avg-severity').textContent = data.avg_severity || 0;
        if (document.getElementById('avg-confidence')) document.getElementById('avg-confidence').textContent = data.avg_confidence || 0;
        if (document.getElementById('incident-count')) document.getElementById('incident-count').textContent = data.incident_count || 0;
    })
    .catch(error => console.error('Error fetching threat stats:', error));
}

function updateSystemMetrics() {
    fetch('/api/system/metrics', {
        headers: getAuthHeaders()
    })
    .then(response => response.json())
    .then(metrics => {
        updateMetricsDisplay(metrics);
    })
    .catch(error => console.error('Error fetching metrics:', error));
}

function updateMetricsDisplay(metrics) {
    // CPU
    const cpuMeter = document.getElementById('cpu-meter');
    const cpuValue = document.getElementById('cpu-value');
    if (cpuMeter && cpuValue) {
        cpuMeter.style.width = metrics.cpu_usage + '%';
        cpuValue.textContent = metrics.cpu_usage.toFixed(1) + '%';
    }
    
    // Memory
    const memMeter = document.getElementById('memory-meter');
    const memValue = document.getElementById('memory-value');
    if (memMeter && memValue) {
        memMeter.style.width = metrics.memory_usage + '%';
        memValue.textContent = metrics.memory_usage.toFixed(1) + '%';
    }
    
    // Network
    const netMeter = document.getElementById('network-meter');
    const netValue = document.getElementById('network-value');
    if (netMeter && netValue) {
        const netPercent = Math.min((metrics.network_traffic / 1000) * 100, 100);
        netMeter.style.width = netPercent + '%';
        netValue.textContent = (metrics.network_traffic / 1024).toFixed(1) + ' Mbps';
    }
    
    // Disk
    const diskMeter = document.getElementById('disk-meter');
    const diskValue = document.getElementById('disk-value');
    if (diskMeter && diskValue && metrics.disk_usage !== undefined) {
        diskMeter.style.width = metrics.disk_usage + '%';
        diskValue.textContent = metrics.disk_usage.toFixed(1) + '%';
    }
}

function loadRecentThreats() {
    fetch('/api/threats/recent?limit=10', {
        headers: getAuthHeaders()
    })
    .then(response => response.json())
    .then(threats => {
        displayThreats(threats);
    })
    .catch(error => console.error('Error loading threats:', error));
}

function displayThreats(threats) {
    const container = document.getElementById('threats-list');
    if (!container) return;
    
    if (threats.length === 0) {
        container.innerHTML = '<p class="text-center text-muted">No threats detected</p>';
        return;
    }
    
    container.innerHTML = threats.map(threat => `
        <div class="threat-row">
            <div class="threat-cell">
                <span class="threat-cell-label">Type</span>
                <span class="threat-cell-value">${threat.threat_type}</span>
            </div>
            <div class="threat-cell">
                <span class="threat-cell-label">Source IP</span>
                <span class="threat-cell-value">${threat.source_ip}</span>
            </div>
            <div class="threat-cell">
                <span class="threat-cell-label">Severity</span>
                <span class="badge badge-${getSeverityClass(threat.severity)}">${threat.severity}/10</span>
            </div>
            <div class="threat-cell">
                <span class="threat-cell-label">Time</span>
                <span class="threat-cell-value">${new Date(threat.detected_at).toLocaleString()}</span>
            </div>
            <div class="threat-actions">
                <button onclick="viewThreatDetails(${threat.id})" title="View Details">
                    <i class="fas fa-eye"></i>
                </button>
                <button onclick="createIncidentFromThreat(${threat.id})" title="Create Incident">
                    <i class="fas fa-flag"></i>
                </button>
                <button onclick="blockThreatSource(${threat.id})" title="Block IP">
                    <i class="fas fa-ban"></i>
                </button>
            </div>
        </div>
    `).join('');
}

function viewThreatDetails(threatId) {
    fetch(`/api/threats/${threatId}`, {
        headers: getAuthHeaders()
    })
    .then(response => response.json())
    .then(threat => {
        showModal('threatDetailsModal', threat);
    })
    .catch(error => console.error('Error loading threat details:', error));
}

function createIncidentFromThreat(threatId) {
    const title = prompt('Enter incident title:');
    if (!title) return;
    
    fetch('/api/incidents', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
            title: title,
            threat_id: threatId,
            status: 'OPEN'
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Incident created successfully', 'success', 'success');
            loadIncidents();
        }
    })
    .catch(error => console.error('Error creating incident:', error));
}

function blockThreatSource(threatId) {
    if (!confirm('Are you sure you want to block this source IP?')) return;
    
    fetch(`/api/threats/${threatId}/block`, {
        method: 'POST',
        headers: getAuthHeaders()
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Threat source blocked', 'success', 'success');
        }
    })
    .catch(error => console.error('Error blocking threat:', error));
}

function updateThreatData(threat) {
    // This function is called when a new threat is detected via WebSocket
    if (document.getElementById('threats-list')) {
        loadRecentThreats();
    }
}

// ===== Incidents Management =====
function loadIncidents() {
    fetch('/api/incidents', {
        headers: getAuthHeaders()
    })
    .then(response => response.json())
    .then(incidents => {
        displayIncidents(incidents);
    })
    .catch(error => console.error('Error loading incidents:', error));
}

function displayIncidents(incidents) {
    const container = document.getElementById('incidents-list');
    if (!container) return;
    
    if (incidents.length === 0) {
        container.innerHTML = '<p class="text-center text-muted">No incidents</p>';
        return;
    }
    
    container.innerHTML = incidents.map(incident => `
        <div class="incident-item">
            <div class="incident-header">
                <div>
                    <div class="incident-title">${incident.title}</div>
                    <div class="incident-meta">
                        <span><strong>ID:</strong> ${incident.incident_id}</span>
                        <span><strong>Status:</strong> ${incident.status}</span>
                        <span><strong>Severity:</strong> <span class="badge badge-${getSeverityClass(incident.severity)}">${incident.severity}/10</span></span>
                    </div>
                </div>
            </div>
            <div class="incident-description">${incident.description || 'No description'}</div>
            <div class="incident-actions">
                <button class="btn btn-sm btn-primary" onclick="editIncident(${incident.id})">
                    <i class="fas fa-edit"></i> Edit
                </button>
                <button class="btn btn-sm btn-secondary" onclick="viewIncidentDetails(${incident.id})">
                    <i class="fas fa-info-circle"></i> Details
                </button>
                <button class="btn btn-sm btn-success" onclick="updateIncidentStatus(${incident.id}, 'RESOLVED')">
                    <i class="fas fa-check"></i> Resolve
                </button>
            </div>
        </div>
    `).join('');
}

function updateIncidentStatus(incidentId, status) {
    fetch(`/api/incidents/${incidentId}`, {
        method: 'PUT',
        headers: getAuthHeaders(),
        body: JSON.stringify({ status })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Incident updated', 'success', 'success');
            loadIncidents();
        }
    })
    .catch(error => console.error('Error updating incident:', error));
}

// ===== Monitoring Control =====
function toggleMonitoring() {
    const isActive = document.getElementById('monitoring-status')?.classList.contains('active');
    
    const endpoint = isActive ? '/api/monitoring/stop' : '/api/monitoring/start';
    
    fetch(endpoint, {
        method: 'POST',
        headers: getAuthHeaders()
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            updateMonitoringStatus(data.status);
        }
    })
    .catch(error => console.error('Error toggling monitoring:', error));
}

function updateMonitoringStatus(status) {
    const badge = document.getElementById('monitoring-status');
    const button = document.getElementById('monitoring-toggle');
    
    if (badge && button) {
        if (status.active) {
            badge.classList.remove('inactive');
            badge.classList.add('active');
            badge.innerHTML = '<i class="fas fa-circle"></i> Monitoring: ON';
            button.innerHTML = '<i class="fas fa-stop"></i> Stop';
        } else {
            badge.classList.remove('active');
            badge.classList.add('inactive');
            badge.innerHTML = '<i class="fas fa-circle"></i> Monitoring: OFF';
            button.innerHTML = '<i class="fas fa-play"></i> Start';
        }
    }
}

// ===== Charts =====
function updateCharts() {
    updateThreatTrendChart();
    updateSeverityDistribution();
    updateThreatTypeChart();
}

function updateThreatTrendChart() {
    fetch('/api/analytics/threat-trends', {
        headers: getAuthHeaders()
    })
    .then(response => response.json())
    .then(data => {
        createLineChart('threatTrendChart', 'Threat Trend (24h)', data.labels, data.values);
    })
    .catch(error => console.error('Error loading threat trends:', error));
}

function updateSeverityDistribution() {
    fetch('/api/analytics/severity-distribution', {
        headers: getAuthHeaders()
    })
    .then(response => response.json())
    .then(data => {
        createPieChart('severityChart', 'Severity Distribution', data.labels, data.values, data.colors);
    })
    .catch(error => console.error('Error loading severity distribution:', error));
}

function updateThreatTypeChart() {
    fetch('/api/analytics/threat-types', {
        headers: getAuthHeaders()
    })
    .then(response => response.json())
    .then(data => {
        createBarChart('threatTypeChart', 'Threats by Type', data.labels, data.values);
    })
    .catch(error => console.error('Error loading threat types:', error));
}

function createLineChart(elementId, title, labels, values) {
    const ctx = document.getElementById(elementId);
    if (!ctx) return;
    
    if (chartsMap[elementId]) chartsMap[elementId].destroy();
    
    chartsMap[elementId] = new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: title,
                data: values,
                borderColor: '#2563eb',
                backgroundColor: 'rgba(37, 99, 235, 0.1)',
                tension: 0.4,
                fill: true,
                pointBackgroundColor: '#2563eb',
                pointBorderColor: '#fff',
                pointBorderWidth: 2,
                pointRadius: 4,
                pointHoverRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(0, 0, 0, 0.05)'
                    }
                }
            }
        }
    });
}

function createPieChart(elementId, title, labels, values, colors) {
    const ctx = document.getElementById(elementId);
    if (!ctx) return;
    
    if (chartsMap[elementId]) chartsMap[elementId].destroy();
    
    chartsMap[elementId] = new Chart(ctx, {
        type: 'doughnut',
        data: {
            labels: labels,
            datasets: [{
                data: values,
                backgroundColor: colors || [
                    '#dc2626', '#f59e0b', '#f97316', '#3b82f6', '#10b981'
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

function createBarChart(elementId, title, labels, values) {
    const ctx = document.getElementById(elementId);
    if (!ctx) return;
    
    if (chartsMap[elementId]) chartsMap[elementId].destroy();
    
    chartsMap[elementId] = new Chart(ctx, {
        type: 'bar',
        data: {
            labels: labels,
            datasets: [{
                label: title,
                data: values,
                backgroundColor: '#2563eb',
                borderRadius: 6
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: true,
            indexAxis: 'y',
            plugins: {
                legend: {
                    display: false
                }
            },
            scales: {
                x: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(0, 0, 0, 0.05)'
                    }
                }
            }
        }
    });
}

// ===== Notifications & Toasts =====
function showNotification(message, type = 'info', severity = 'info') {
    const container = document.querySelector('.toast-container') || createToastContainer();
    
    const toast = document.createElement('div');
    toast.className = `toast alert-${severity}`;
    toast.innerHTML = `
        <i class="fas fa-${getIconForType(type)}"></i>
        <div>
            <strong>${type.charAt(0).toUpperCase() + type.slice(1)}</strong>
            <p>${message}</p>
        </div>
        <button onclick="this.parentElement.remove()" class="btn-close"></button>
    `;
    
    container.appendChild(toast);
    
    setTimeout(() => {
        toast.remove();
    }, 5000);
}

function createToastContainer() {
    const container = document.createElement('div');
    container.className = 'toast-container';
    document.body.appendChild(container);
    return container;
}

function getIconForType(type) {
    const icons = {
        'success': 'check-circle',
        'warning': 'exclamation-circle',
        'error': 'times-circle',
        'info': 'info-circle',
        'critical': 'skull'
    };
    return icons[type] || 'info-circle';
}

// ===== Modals =====
function showModal(modalId, data = null) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.add('show');
        if (data) {
            populateModal(modalId, data);
        }
    }
}

function closeModal(modalId) {
    const modal = document.getElementById(modalId);
    if (modal) {
        modal.classList.remove('show');
    }
}

function populateModal(modalId, data) {
    // This would populate modal fields with data
    console.log('Populating modal:', modalId, data);
}

// ===== Theme Toggle =====
function toggleTheme() {
    currentTheme = currentTheme === 'light' ? 'dark' : 'light';
    document.body.classList.toggle('dark-mode');
    localStorage.setItem('theme', currentTheme);
}

function applyTheme() {
    if (currentTheme === 'dark') {
        document.body.classList.add('dark-mode');
    }
}

// ===== Utilities =====
function getSeverityClass(severity) {
    if (severity >= 8) return 'critical';
    if (severity >= 6) return 'high';
    if (severity >= 4) return 'medium';
    return 'low';
}

function formatDate(date) {
    return new Date(date).toLocaleDateString('en-US', {
        year: 'numeric',
        month: 'short',
        day: 'numeric',
        hour: '2-digit',
        minute: '2-digit'
    });
}

// ===== Missing Functionalities (Filter, Incident, Reports, Map, Analytics) =====
function filterThreats() {
    const type = document.getElementById('filter-threat-type')?.value || '';
    const severitySelect = document.getElementById('filter-severity')?.value || '';
    const ip = document.getElementById('filter-ip')?.value || '';
    
    let severity = '';
    if (severitySelect === 'critical') severity = '8';
    else if (severitySelect === 'high') severity = '6';
    else if (severitySelect === 'medium') severity = '4';
    else if (severitySelect === 'low') severity = '1';

    let url = `/api/threats?limit=50`;
    if (type) url += `&type=${encodeURIComponent(type)}`;
    if (severity) url += `&severity=${encodeURIComponent(severity)}`;
    if (ip) url += `&ip=${encodeURIComponent(ip)}`;
    
    fetch(url, {
        headers: getAuthHeaders()
    })
    .then(response => response.json())
    .then(data => {
        const container = document.getElementById('threats-filtered-list');
        if (!container) return;
        
        const threats = data.threats || [];
        if (threats.length === 0) {
            container.innerHTML = '<p class="text-center text-muted">No threats found matching the filter criteria</p>';
            return;
        }
        
        container.innerHTML = threats.map(threat => `
            <div class="threat-row">
                <div class="threat-cell">
                    <span class="threat-cell-label">Type</span>
                    <span class="threat-cell-value">${threat.threat_type}</span>
                </div>
                <div class="threat-cell">
                    <span class="threat-cell-label">Source IP</span>
                    <span class="threat-cell-value">${threat.source_ip}</span>
                </div>
                <div class="threat-cell">
                    <span class="threat-cell-label">Severity</span>
                    <span class="badge badge-${getSeverityClass(threat.severity)}">${threat.severity}/10</span>
                </div>
                <div class="threat-cell">
                    <span class="threat-cell-label">Time</span>
                    <span class="threat-cell-value">${new Date(threat.detected_at).toLocaleString()}</span>
                </div>
                <div class="threat-actions">
                    <button onclick="viewThreatDetails(${threat.id})" title="View Details">
                        <i class="fas fa-eye"></i>
                    </button>
                    <button onclick="createIncidentFromThreat(${threat.id})" title="Create Incident">
                        <i class="fas fa-flag"></i>
                    </button>
                    <button onclick="blockThreatSource(${threat.id})" title="Block IP">
                        <i class="fas fa-ban"></i>
                    </button>
                </div>
            </div>
        `).join('');
    })
    .catch(error => {
        console.error('Error filtering threats:', error);
        showNotification('Error filtering threats', 'error', 'danger');
    });
}

function createIncident() {
    const title = document.getElementById('incident-title')?.value;
    const description = document.getElementById('incident-description')?.value;
    const severity = document.getElementById('incident-severity')?.value;
    const threatType = document.getElementById('incident-threat-type')?.value;
    
    if (!title) {
        showNotification('Incident title is required', 'warning', 'warning');
        return;
    }
    
    fetch('/api/incidents', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
            title: title,
            description: description || '',
            severity: parseInt(severity) || 5,
            threat_type: threatType || ''
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Incident created successfully', 'success', 'success');
            if (document.getElementById('incident-title')) document.getElementById('incident-title').value = '';
            if (document.getElementById('incident-description')) document.getElementById('incident-description').value = '';
            loadIncidents();
        } else {
            showNotification(data.message || 'Error creating incident', 'error', 'danger');
        }
    })
    .catch(error => {
        console.error('Error creating incident:', error);
        showNotification('Error creating incident', 'error', 'danger');
    });
}

function generateReport() {
    const type = document.getElementById('report-type')?.value || 'daily';
    const format = document.getElementById('export-format')?.value || 'pdf';
    const startDate = document.getElementById('report-start-date')?.value || '';
    const endDate = document.getElementById('report-end-date')?.value || '';
    
    fetch('/api/reports/generate', {
        method: 'POST',
        headers: getAuthHeaders(),
        body: JSON.stringify({
            report_type: type,
            export_format: format,
            start_date: startDate,
            end_date: endDate
        })
    })
    .then(response => response.json())
    .then(data => {
        if (data.success) {
            showNotification('Report generated successfully', 'success', 'success');
            loadReports();
        } else {
            showNotification(data.message || 'Error generating report', 'error', 'danger');
        }
    })
    .catch(error => {
        console.error('Error generating report:', error);
        showNotification('Error generating report', 'error', 'danger');
    });
}

function loadReports() {
    fetch('/api/reports', {
        headers: getAuthHeaders()
    })
    .then(response => response.json())
    .then(reports => {
        const tbody = document.getElementById('reports-table-body');
        if (!tbody) return;
        
        if (reports.length === 0) {
            tbody.innerHTML = '<tr><td colspan="5" style="text-align: center; color: var(--text-secondary);">No reports generated yet</td></tr>';
            return;
        }
        
        tbody.innerHTML = reports.map(report => `
            <tr>
                <td><strong>${report.title}</strong></td>
                <td><span class="badge badge-secondary">${report.report_type.toUpperCase()}</span></td>
                <td>${new Date(report.generated_at).toLocaleString()}</td>
                <td><span class="badge badge-info">${report.file_format.toUpperCase()}</span></td>
                <td>
                    <button class="btn btn-sm btn-primary" onclick="downloadReport(${report.id})">
                        <i class="fas fa-download"></i> Download
                    </button>
                </td>
            </tr>
        `).join('');
    })
    .catch(error => console.error('Error loading reports:', error));
}

function downloadReport(id) {
    fetch(`/api/reports/${id}/download`, {
        headers: getAuthHeaders()
    })
    .then(response => {
        if (!response.ok) throw new Error('Download failed');
        return response.blob();
    })
    .then(blob => {
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.style.display = 'none';
        a.href = url;
        a.download = `report_${id}.json`;
        document.body.appendChild(a);
        a.click();
        window.URL.revokeObjectURL(url);
        showNotification('Report downloaded successfully', 'success', 'success');
    })
    .catch(error => {
        console.error('Error downloading report:', error);
        showNotification('Error downloading report', 'error', 'danger');
    });
}

let leafletMap = null;
function initMap() {
    const container = document.getElementById('map-container');
    if (!container) return;
    
    container.innerHTML = '<div id="threat-map" style="height: 600px; width: 100%; border-radius: 0.75rem;"></div>';
    
    leafletMap = L.map('threat-map').setView([20, 0], 2);
    
    L.tileLayer('https://{s}.tile.openstreetmap.org/{z}/{x}/{y}.png', {
        attribution: '&copy; <a href="https://www.openstreetmap.org/copyright">OpenStreetMap</a> contributors'
    }).addTo(leafletMap);
    
    fetch('/api/analytics/geolocation', {
        headers: getAuthHeaders()
    })
    .then(response => response.json())
    .then(markers => {
        markers.forEach(marker => {
            if (marker.latitude && marker.longitude) {
                L.marker([marker.latitude, marker.longitude])
                    .addTo(leafletMap)
                    .bindPopup(`
                        <strong>IP:</strong> ${marker.ip_address}<br/>
                        <strong>Location:</strong> ${marker.city}, ${marker.country}<br/>
                        <strong>ISP:</strong> ${marker.isp}<br/>
                        <strong>Threat Count:</strong> ${marker.threat_count}
                    `);
            }
        });
    })
    .catch(error => console.error('Error loading map markers:', error));
    
    fetch('/api/analytics/origins', {
        headers: getAuthHeaders()
    })
    .then(response => response.json())
    .then(origins => {
        const originsContainer = document.getElementById('threat-origins');
        if (!originsContainer) return;
        
        if (origins.length === 0) {
            originsContainer.innerHTML = '<p class="text-center text-muted">No geolocation data available</p>';
            return;
        }
        
        originsContainer.innerHTML = `
            <table class="table">
                <thead>
                    <tr>
                        <th>Country</th>
                        <th>Threat Count</th>
                        <th>Percentage</th>
                    </tr>
                </thead>
                <tbody>
                    ${origins.map(origin => `
                        <tr>
                            <td><strong>${origin.country}</strong></td>
                            <td>${origin.count}</td>
                            <td>
                                <div style="display: flex; align-items: center; gap: 0.5rem;">
                                    <div style="flex-grow: 1; background: var(--bg-secondary); height: 8px; border-radius: 4px; overflow: hidden;">
                                        <div style="width: ${origin.percentage}%; background: var(--primary); height: 100%;"></div>
                                    </div>
                                    <span>${origin.percentage}%</span>
                                </div>
                            </td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    })
    .catch(error => console.error('Error loading threat origins:', error));
}

function updateAnalyticsTab() {
    fetch('/api/analytics/overview', {
        headers: getAuthHeaders()
    })
    .then(response => response.json())
    .then(data => {
        const overviewContainer = document.getElementById('threat-overview');
        if (!overviewContainer) return;
        
        let breakdownHtml = '';
        if (data.breakdown && Object.keys(data.breakdown).length > 0) {
            breakdownHtml = '<ul>' + Object.entries(data.breakdown).map(([type, count]) => `
                <li><strong>${type}:</strong> ${count} threats</li>
            `).join('') + '</ul>';
        } else {
            breakdownHtml = '<p>No threat breakdown data available.</p>';
        }
        
        overviewContainer.innerHTML = `
            <div>
                <p><strong>Total Threats Classified:</strong> ${data.total_threats || 0}</p>
                <p><strong>Incident Resolution Rate:</strong> ${data.resolution_rate || 100}%</p>
                <p><strong>Threats Breakdown:</strong></p>
                ${breakdownHtml}
            </div>
        `;
    })
    .catch(error => console.error('Error fetching analytics overview:', error));

    fetch('/api/analytics/top-ips', {
        headers: getAuthHeaders()
    })
    .then(response => response.json())
    .then(ips => {
        const ipsContainer = document.getElementById('top-ips');
        if (!ipsContainer) return;
        
        if (ips.length === 0) {
            ipsContainer.innerHTML = '<p class="text-muted">No attacker IP data available</p>';
            return;
        }
        
        ipsContainer.innerHTML = `
            <table class="table" style="margin: 0;">
                <thead>
                    <tr>
                        <th>IP Address</th>
                        <th>Occurrences</th>
                        <th>Max Severity</th>
                    </tr>
                </thead>
                <tbody>
                    ${ips.map(item => `
                        <tr>
                            <td><code>${item.ip}</code></td>
                            <td>${item.count}</td>
                            <td><span class="badge badge-${getSeverityClass(item.max_severity)}">${item.max_severity}/10</span></td>
                        </tr>
                    `).join('')}
                </tbody>
            </table>
        `;
    })
    .catch(error => console.error('Error fetching top attacker IPs:', error));

    fetch('/api/analytics/time-of-day', {
        headers: getAuthHeaders()
    })
    .then(response => response.json())
    .then(data => {
        createLineChart('threatTimeChart', 'Threats by Hour', data.labels, data.values);
    })
    .catch(error => console.error('Error fetching time of day analytics:', error));
}

// ===== Initialization =====
document.addEventListener('DOMContentLoaded', () => {
    // Apply saved theme
    applyTheme();
    
    // Check authentication
    if (isAuthenticated()) {
        currentUser = JSON.parse(localStorage.getItem('user'));
        initializeSocket();
        updateDashboard();
        
        // Update dashboard every 10 seconds
        setInterval(updateDashboard, 10000);
    } else {
        window.location.href = '/login';
    }
    
    // Close modals on background click
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.classList.remove('show');
            }
        });
    });
});

// Logout on window close
window.addEventListener('beforeunload', () => {
    if (socket) socket.disconnect();
});
