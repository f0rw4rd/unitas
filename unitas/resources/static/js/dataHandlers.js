// Global state
let serviceTypes = new Set();
let subnetGroups = {};

// Functions to handle reading and parsing scan data
function handleFile(file) {
    if (!file.name.endsWith('.json')) {
        showError('Please select a JSON file (.json)');
        return;
    }

    showLoading();

    const reader = new FileReader();

    reader.onload = function (e) {
        try {
            window.scanData = JSON.parse(e.target.result);
            validateAndDisplayData(window.scanData);
        } catch (error) {
            console.error('Error parsing JSON:', error);
            showError('Invalid JSON file. Please select a valid Unitas export file.');
            hideLoading();
        }
    };

    reader.onerror = function () {
        showError('Error reading file');
        hideLoading();
    };

    reader.readAsText(file);
}

function validateAndDisplayData(data) {
    // Basic validation of data structure
    if (!data.hosts || !Array.isArray(data.hosts)) {
        showError('Invalid data format: Missing hosts array');
        hideLoading();
        return;
    }

    // Switch views
    document.getElementById('initial-screen').classList.add('hidden');
    document.getElementById('data-view').classList.remove('hidden');
    document.getElementById('error-message').classList.add('hidden');

    // Display scan info
    if (data.metadata) {
        document.getElementById('scan-date').textContent = `Generated: ${data.metadata.generated || 'Unknown'}`;
        document.getElementById('scan-version').textContent = `Unitas ${data.metadata.version || 'Unknown'}`;
    } else {
        document.getElementById('scan-date').textContent = 'Generated: Unknown';
        document.getElementById('scan-version').textContent = 'Unitas Unknown';
    }

    // Initialize the visualization
    updateStats();
    populateTables();
    populateServiceFilter();
    setupEventHandlers();
    hideLoading();
}

// Utility functions for managing the UI state
function showError(message) {
    const errorMessage = document.getElementById('error-message');
    errorMessage.textContent = message;
    errorMessage.classList.remove('hidden');
}

function showLoading() {
    document.getElementById('loading-overlay').style.display = 'flex';
}

function hideLoading() {
    document.getElementById('loading-overlay').style.display = 'none';
}

// Stats calculations
function updateStats() {
    if (!window.scanData) return;

    document.getElementById('total-hosts').textContent = window.scanData.hosts.length;

    let totalPorts = 0;
    window.scanData.hosts.forEach(host => {
        totalPorts += host.ports.length;
    });
    document.getElementById('total-ports').textContent = totalPorts;

    document.getElementById('up-hosts').textContent = window.scanData.hostsUp ? window.scanData.hostsUp.length : 0;

    // Get unique services
    serviceTypes.clear();
    window.scanData.hosts.forEach(host => {
        host.ports.forEach(port => {
            const cleanService = port.service.replace('?', '');
            serviceTypes.add(cleanService);
        });
    });
    document.getElementById('services-count').textContent = serviceTypes.size;
}

function populateServiceFilter() {
    const serviceFilter = document.getElementById('service-filter');
    serviceFilter.innerHTML = '<option value="all">All Services</option>';

    Array.from(serviceTypes).sort().forEach(service => {
        const option = document.createElement('option');
        option.value = service;
        option.textContent = service;
        serviceFilter.appendChild(option);
    });
}

function processSubnets() {
    subnetGroups = {};

    window.scanData.hosts.forEach(host => {
        const subnet = getSubnet(host.ip);

        if (!subnetGroups[subnet]) {
            subnetGroups[subnet] = {
                hosts: new Set(),
                services: new Set()
            };
        }

        subnetGroups[subnet].hosts.add(host.ip);

        host.ports.forEach(port => {
            subnetGroups[subnet].services.add(port.service.replace("?", ""));
        });
    });

    if (window.scanData.hostsUp) {
        window.scanData.hostsUp.forEach(host => {
            const subnet = getSubnet(host.ip);

            if (!subnetGroups[subnet]) {
                subnetGroups[subnet] = {
                    hosts: new Set(),
                    services: new Set()
                };
            }

            subnetGroups[subnet].hosts.add(host.ip);
        });
    }
}

function getSubnet(ip) {
    const parts = ip.split(".");
    return parts.length === 4 ? `${parts[0]}.${parts[1]}.${parts[2]}` : ip;
}

function getSubnetGroup(ip) {
    return getSubnet(ip);
}

// Export functions
function exportNetworkAsMarkdown() {
    if (!window.scanData) return;

    // Generate markdown content
    let markdown = "|IP|Hostname|Port|Status|Comment|\n|--|--|--|--|---|\n";

    window.scanData.hosts.forEach(host => {
        host.ports.forEach(port => {
            const ip = host.ip;
            const hostname = host.hostname || '';
            const portInfo = `${port.port}/${port.protocol}(${port.service})`;
            const state = port.state || 'TBD';
            const comment = port.comment || '';

            markdown += `|${ip}|${hostname}|${portInfo}|${state}|${comment}|\n`;
        });
    });

    // Create and download file
    const blob = new Blob([markdown], { type: 'text/markdown' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = 'unitas_export.md';
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
}
