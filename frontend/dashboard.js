// Dashboard JavaScript for ForenX-Sentinel
const API_BASE = 'http://localhost:8000';

async function fetchSystemStats() {
    try {
        const response = await fetch(`${API_BASE}/api/stats/`);
        const data = await response.json();
        
        // Update dashboard cards
        document.getElementById('totalLogs').textContent = 
            data.total_events.toLocaleString();
        document.getElementById('uniqueIPs').textContent = 
            data.unique_ips.toLocaleString();
        document.getElementById('dataVolume').textContent = 
            `${Math.round(data.total_data_volume / (1024 * 1024))} MB`;
        
        // Fetch endpoint analysis for high-risk count
        const endpoints = await fetchEndpoints();
        const highRiskCount = endpoints.filter(e => e.risk_level === 'High').length;
        document.getElementById('highRiskEndpoints').textContent = highRiskCount;
        
        updateActivityChart(data);
        updateEndpointsTable(endpoints);
        
    } catch (error) {
        console.error('Error fetching stats:', error);
    }
}

async function uploadLog() {
    const fileInput = document.getElementById('logFile');
    const logType = document.getElementById('logType').value;
    const resultDiv = document.getElementById('uploadResult');
    
    if (!fileInput.files.length) {
        resultDiv.innerHTML = '<p class="error">Please select a log file</p>';
        return;
    }
    
    const formData = new FormData();
    formData.append('file', fileInput.files[0]);
    
    try {
        resultDiv.innerHTML = '<p class="loading">⏳ Uploading and analyzing logs...</p>';
        
        const response = await fetch(`${API_BASE}/api/upload/?log_type=${logType}`, {
            method: 'POST',
            body: formData
        });
        
        const data = await response.json();
        
        resultDiv.innerHTML = `
            <div class="success">
                <p>✅ ${data.message}</p>
                <p><strong>File:</strong> ${data.filename}</p>
                <p><strong>Events Ingested:</strong> ${data.events_ingested.toLocaleString()}</p>
            </div>
        `;
        
        // Refresh dashboard after successful upload
        setTimeout(fetchSystemStats, 1000);
        
    } catch (error) {
        resultDiv.innerHTML = `<p class="error">❌ Upload failed: ${error.message}</p>`;
    }
}

async function fetchEndpoints() {
    try {
        const response = await fetch(`${API_BASE}/api/endpoints/?limit=20`);
        return await response.json();
    } catch (error) {
        console.error('Error fetching endpoints:', error);
        return [];
    }
}

function updateEndpointsTable(endpoints) {
    const tbody = document.getElementById('endpointsBody');
    tbody.innerHTML = '';
    
    endpoints.forEach(endpoint => {
        const riskClass = `risk-${endpoint.risk_level.toLowerCase()}`;
        
        const row = document.createElement('tr');
        row.innerHTML = `
            <td><code>${endpoint.endpoint}</code></td>
            <td>${endpoint.total_hits.toLocaleString()}</td>
            <td>${endpoint.unique_ips}</td>
            <td>${Math.round(endpoint.total_data_volume / 1024)} KB</td>
            <td><span class="${riskClass}">${endpoint.risk_score}</span></td>
            <td><span class="${riskClass}">${endpoint.risk_level}</span></td>
        `;
        tbody.appendChild(row);
    });
}

function updateActivityChart(stats) {
    const ctx = document.getElementById('activityChart').getContext('2d');
    
    // Sample data - in production, this would come from time-series API
    const labels = ['00:00', '04:00', '08:00', '12:00', '16:00', '20:00'];
    const data = [120, 190, 300, 500, 200, 150];
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: labels,
            datasets: [{
                label: 'Requests per hour',
                data: data,
                borderColor: '#60a5fa',
                backgroundColor: 'rgba(96, 165, 250, 0.1)',
                borderWidth: 2,
                fill: true,
                tension: 0.4
            }]
        },
        options: {
            responsive: true,
            plugins: {
                legend: {
                    labels: {
                        color: '#f8fafc'
                    }
                }
            },
            scales: {
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.
