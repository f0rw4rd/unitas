// Main application initialization
document.addEventListener('DOMContentLoaded', function () {
    // DOM Elements
    const initialScreen = document.getElementById('initial-screen');
    const dataView = document.getElementById('data-view');
    const dropArea = document.getElementById('drop-area');
    const fileInput = document.getElementById('file-input');
    const errorMessage = document.getElementById('error-message');
    const reloadBtn = document.getElementById('reload-btn');
    const exportMarkdownBtn = document.getElementById('export-markdown-btn');
    const loadingOverlay = document.getElementById('loading-overlay');
    const nodeDetails = document.getElementById('node-details');
    const searchInput = document.getElementById('search');

    // Setup drag and drop handlers
    ['dragenter', 'dragover', 'dragleave', 'drop'].forEach(eventName => {
        dropArea.addEventListener(eventName, preventDefaults, false);
    });

    function preventDefaults(e) {
        e.preventDefault();
        e.stopPropagation();
    }

    ['dragenter', 'dragover'].forEach(eventName => {
        dropArea.addEventListener(eventName, highlight, false);
    });

    ['dragleave', 'drop'].forEach(eventName => {
        dropArea.addEventListener(eventName, unhighlight, false);
    });

    function highlight() {
        dropArea.classList.add('highlight');
    }

    function unhighlight() {
        dropArea.classList.remove('highlight');
    }

    // Handle file drop
    dropArea.addEventListener('drop', function (e) {
        const dt = e.dataTransfer;
        const files = dt.files;

        if (files.length === 1) {
            handleFile(files[0]);
        } else {
            showError('Please drop a single JSON file.');
        }
    }, false);

    // Handle file input
    fileInput.addEventListener('change', function () {
        if (this.files.length === 1) {
            handleFile(this.files[0]);
        } else {
            showError('Please select a single JSON file.');
        }
    });

    // Handle reload button
    reloadBtn.addEventListener('click', function () {
        initialScreen.classList.remove('hidden');
        dataView.classList.add('hidden');
        errorMessage.classList.add('hidden');
        fileInput.value = '';
        window.scanData = null;

        if (network) {
            network.destroy();
            network = null;
        }

        if (minimapNetwork) {
            minimapNetwork.destroy();
            minimapNetwork = null;
        }

        pinnedNodes.clear();
        filteredItems.hosts.clear();
        filteredItems.services.clear();
        filteredItems.nodes.clear();
        filteredItems.edges.clear();
    });

    // Handle export markdown button
    exportMarkdownBtn.addEventListener('click', exportNetworkAsMarkdown);

    // Handle export CSV button
    const exportCsvBtn = document.getElementById('export-csv-btn');
    exportCsvBtn.addEventListener('click', exportCurrentViewAsCSV);

    // Navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
            document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));

            item.classList.add('active');
            const viewId = item.getAttribute('data-view');
            document.getElementById(viewId).classList.add('active');

            if (viewId === 'graph-view' && window.scanData) {
                if (!network) {
                    renderGraph();
                }
            }
        });
    });

    // Search functionality
    searchInput.addEventListener('input', function () {
        const searchTerm = this.value.toLowerCase();
        filterTables(searchTerm);
    });

    // Status filter for ports view
    document.querySelectorAll('.status-btn').forEach(btn => {
        btn.addEventListener('click', () => {
            document.querySelectorAll('.status-btn').forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            filterPortsTableByStatus(btn.getAttribute('data-status').toLowerCase());
        });
    });

    // Setup network graph event handlers
    setupNetworkEventHandlers();

    // Check for auto-load data from URL parameters
    checkForAutoLoadData();

    // Setup keyboard shortcuts
    setupKeyboardShortcuts();

    // Setup shortcuts panel toggle
    setupShortcutsPanel();

    // Setup table sorting
    setupTableSorting();
});

function setupNetworkEventHandlers() {
    // Graph control buttons
    document.getElementById('pin-node').addEventListener('click', togglePinNode);
    document.getElementById('focus-node').addEventListener('click', focusNode);
    document.getElementById('apply-filters').addEventListener('click', applyFilters);
    document.getElementById('reset-filters').addEventListener('click', resetFilters);
    document.getElementById('toggle-minimap').addEventListener('click', toggleMinimap);
    document.getElementById('toggle-physics').addEventListener('click', togglePhysics);
    document.getElementById('fit-graph').addEventListener('click', fitGraph);
    document.getElementById('export-png').addEventListener('click', exportNetworkImage);
    document.getElementById('save-view').addEventListener('click', saveCurrentView);
    document.getElementById('run-analysis').addEventListener('click', runAnalysis);

    // Filter controls
    document.getElementById('show-up-hosts').addEventListener('change', refreshGraph);
    document.getElementById('show-uncertain').addEventListener('change', applyFilters);
    document.getElementById('highlight-tls').addEventListener('change', highlightTlsServices);

    // Node size slider
    document.getElementById('node-size').addEventListener('input', function () {
        if (network) {
            network.setOptions({
                nodes: {
                    scaling: {
                        min: Math.max(5, parseInt(this.value) - 10),
                        max: parseInt(this.value) + 10
                    }
                }
            });
        }
    });

    // Layout selection
    document.querySelectorAll('input[name="layout"]').forEach(radio => {
        radio.addEventListener('change', function () {
            if (!network) return;

            const positions = network.getPositions();
            network.setOptions({
                layout: getSelectedLayout()
            });

            if (this.value !== 'hierarchical') {
                pinnedNodes.forEach(nodeId => {
                    if (positions[nodeId]) {
                        nodesDataset.update({
                            id: nodeId,
                            fixed: { x: true, y: true },
                            x: positions[nodeId].x,
                            y: positions[nodeId].y
                        });
                    }
                });
            }
        });
    });
}

function setupEventHandlers() {
    // Setup navigation handlers
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
            document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));

            item.classList.add('active');
            const viewId = item.getAttribute('data-view');
            document.getElementById(viewId).classList.add('active');

            if (viewId === 'graph-view' && window.scanData) {
                if (!network) {
                    renderGraph();
                }
            }
        });
    });
}

function checkForAutoLoadData() {
    // Function to check for URL parameters to auto-load data
    const urlParams = new URLSearchParams(window.location.search);
    const dataUrl = urlParams.get('data');

    if (dataUrl) {
        // Auto-load data from the specified URL
        fetch(dataUrl)
            .then(response => {
                if (!response.ok) {
                    throw new Error('Network response was not ok');
                }
                return response.json();
            })
            .then(data => {
                window.scanData = data;
                validateAndDisplayData(data);
            })
            .catch(error => {
                console.error('Error loading data:', error);
                showError(`Error loading data: ${error.message}`);
            });
    }

    // Check if we have data in localStorage
    const storedData = localStorage.getItem('unitasData');
    if (storedData && !dataUrl) {
        try {
            const data = JSON.parse(storedData);
            window.scanData = data;
            validateAndDisplayData(data);
        } catch (error) {
            console.error('Error loading stored data:', error);
            localStorage.removeItem('unitasData');
        }
    }
}

// Add auto-load functionality (if using URL-loaded JSON data)
function tryLoadFromUrl(url) {
    showLoading();

    fetch(url)
        .then(response => {
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            window.scanData = data;
            validateAndDisplayData(data);
        })
        .catch(error => {
            console.error('Error loading data:', error);
            showError(`Error loading data: ${error.message}`);
            hideLoading();
        });
}

// Setup keyboard shortcuts
function setupKeyboardShortcuts() {
    document.addEventListener('keydown', function(e) {
        // Ignore shortcuts when typing in input fields
        if (e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'SELECT') {
            // Allow Ctrl+A for select all in search
            if (e.ctrlKey && e.key === 'a' && e.target.id === 'search') {
                return;
            }
            // Allow Escape to blur input fields
            if (e.key === 'Escape') {
                e.target.blur();
                return;
            }
            return;
        }

        // Handle keyboard shortcuts
        switch(e.key) {
            case '/':
            case 'f':
                if (e.ctrlKey || (!e.ctrlKey && e.key === '/')) {
                    e.preventDefault();
                    document.getElementById('search').focus();
                }
                break;
            case 'Escape':
                e.preventDefault();
                // Clear search and blur
                const searchInput = document.getElementById('search');
                searchInput.value = '';
                searchInput.blur();
                filterTables('');
                break;
            case '1':
                e.preventDefault();
                switchToView('hosts-view');
                break;
            case '2':
                e.preventDefault();
                switchToView('ports-view');
                break;
            case '3':
                e.preventDefault();
                switchToView('services-view');
                break;
            case '4':
                e.preventDefault();
                switchToView('up-hosts-view');
                break;
            case '5':
                e.preventDefault();
                switchToView('graph-view');
                break;
            case 'r':
                if (e.ctrlKey) {
                    e.preventDefault();
                    // Reload data
                    document.getElementById('reload-btn').click();
                }
                break;
            case 'e':
                if (e.ctrlKey) {
                    e.preventDefault();
                    // Export markdown
                    document.getElementById('export-markdown-btn').click();
                }
                break;
        }
    });
}

// Helper function to switch views
function switchToView(viewId) {
    document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    
    const navItem = document.querySelector(`[data-view="${viewId}"]`);
    if (navItem) {
        navItem.classList.add('active');
        document.getElementById(viewId).classList.add('active');
        
        if (viewId === 'graph-view' && window.scanData && !network) {
            renderGraph();
        }
    }
}

// Setup shortcuts panel toggle
function setupShortcutsPanel() {
    const shortcutsToggle = document.getElementById('shortcuts-toggle');
    const shortcutsPanel = document.getElementById('shortcuts-panel');
    
    shortcutsToggle.addEventListener('click', function(e) {
        e.stopPropagation();
        shortcutsPanel.classList.toggle('hidden');
    });
    
    // Close panel when clicking outside
    document.addEventListener('click', function(e) {
        if (!shortcutsPanel.contains(e.target) && !shortcutsToggle.contains(e.target)) {
            shortcutsPanel.classList.add('hidden');
        }
    });
}

// Setup table sorting functionality
function setupTableSorting() {
    document.querySelectorAll('th.sortable').forEach(header => {
        header.addEventListener('click', function() {
            const table = this.closest('table');
            const tbody = table.querySelector('tbody');
            const rows = Array.from(tbody.querySelectorAll('tr'));
            const sortField = this.dataset.sort;
            const currentSort = this.classList.contains('sort-asc') ? 'asc' : 
                               this.classList.contains('sort-desc') ? 'desc' : null;
            
            // Remove sort classes from all headers in this table
            table.querySelectorAll('th.sortable').forEach(h => {
                h.classList.remove('sort-asc', 'sort-desc');
            });
            
            // Determine new sort direction
            let newSort = 'asc';
            if (currentSort === 'asc') {
                newSort = 'desc';
            }
            
            // Add sort class to current header
            this.classList.add(newSort === 'asc' ? 'sort-asc' : 'sort-desc');
            
            // Sort rows
            rows.sort((a, b) => {
                let aVal = getSortValue(a, sortField);
                let bVal = getSortValue(b, sortField);
                
                // Handle different data types
                if (sortField === 'port' || sortField === 'count') {
                    aVal = parseInt(aVal) || 0;
                    bVal = parseInt(bVal) || 0;
                } else if (sortField === 'ip') {
                    aVal = ipToNumber(aVal);
                    bVal = ipToNumber(bVal);
                } else {
                    aVal = aVal.toLowerCase();
                    bVal = bVal.toLowerCase();
                }
                
                if (aVal < bVal) return newSort === 'asc' ? -1 : 1;
                if (aVal > bVal) return newSort === 'asc' ? 1 : -1;
                return 0;
            });
            
            // Re-append sorted rows
            rows.forEach(row => tbody.appendChild(row));
        });
    });
}

// Get sort value from table row
function getSortValue(row, field) {
    const cells = row.querySelectorAll('td');
    const tableId = row.closest('table').id;
    
    switch(tableId) {
        case 'hosts-table':
            const hostsFieldMap = { ip: 0, hostname: 1, mac: 2, vendor: 3, ports: 4 };
            return cells[hostsFieldMap[field]]?.textContent.trim() || '';
        case 'ports-table':
            const portsFieldMap = { ip: 0, hostname: 1, port: 2, protocol: 3, service: 4, status: 5, comment: 6 };
            return cells[portsFieldMap[field]]?.textContent.trim() || '';
        case 'services-table':
            const servicesFieldMap = { service: 0, count: 1, hosts: 2 };
            return cells[servicesFieldMap[field]]?.textContent.trim() || '';
        default:
            return '';
    }
}

// Convert IP address to number for proper sorting
function ipToNumber(ip) {
    if (!ip || ip === '-') return 0;
    return ip.split('.').reduce((acc, octet) => (acc << 8) + parseInt(octet), 0);
}

// Export current view as CSV
function exportCurrentViewAsCSV() {
    const activeView = document.querySelector('.view.active');
    if (!activeView) return;

    let csvContent = '';
    let filename = 'unitas-export.csv';

    switch(activeView.id) {
        case 'hosts-view':
            csvContent = exportHostsAsCSV();
            filename = 'unitas-hosts.csv';
            break;
        case 'ports-view':
            csvContent = exportPortsAsCSV();
            filename = 'unitas-ports.csv';
            break;
        case 'services-view':
            csvContent = exportServicesAsCSV();
            filename = 'unitas-services.csv';
            break;
        case 'up-hosts-view':
            csvContent = exportUpHostsAsCSV();
            filename = 'unitas-up-hosts.csv';
            break;
        default:
            showError('CSV export not available for this view');
            return;
    }

    if (csvContent) {
        downloadCSV(csvContent, filename);
    }
}

// Export hosts table as CSV
function exportHostsAsCSV() {
    if (!window.scanData || !window.scanData.hosts) return '';
    
    const headers = ['IP', 'Hostname', 'MAC Address', 'Vendor', 'Open Ports'];
    let csv = headers.join(',') + '\n';
    
    Object.values(window.scanData.hosts).forEach(host => {
        const ports = host.ports.map(p => `${p.port}/${p.protocol}(${p.service})`).join(';');
        const row = [
            `"${host.ip}"`,
            `"${host.hostname || ''}"`,
            `"${host.mac_address || ''}"`,
            `"${host.vendor || ''}"`,
            `"${ports}"`
        ];
        csv += row.join(',') + '\n';
    });
    
    return csv;
}

// Export ports table as CSV
function exportPortsAsCSV() {
    if (!window.scanData || !window.scanData.hosts) return '';
    
    const headers = ['IP', 'Hostname', 'Port', 'Protocol', 'Service', 'Status', 'Comment'];
    let csv = headers.join(',') + '\n';
    
    Object.values(window.scanData.hosts).forEach(host => {
        host.ports.forEach(port => {
            const row = [
                `"${host.ip}"`,
                `"${host.hostname || ''}"`,
                `"${port.port}"`,
                `"${port.protocol}"`,
                `"${port.service}"`,
                `"${port.state || 'TBD'}"`,
                `"${port.comment || ''}"`
            ];
            csv += row.join(',') + '\n';
        });
    });
    
    return csv;
}

// Export services table as CSV
function exportServicesAsCSV() {
    if (!window.scanData || !window.scanData.hosts) return '';
    
    const serviceMap = new Map();
    
    Object.values(window.scanData.hosts).forEach(host => {
        host.ports.forEach(port => {
            const service = port.service;
            if (!serviceMap.has(service)) {
                serviceMap.set(service, { count: 0, hosts: new Set() });
            }
            serviceMap.get(service).count++;
            serviceMap.get(service).hosts.add(host.ip);
        });
    });
    
    const headers = ['Service', 'Count', 'Hosts'];
    let csv = headers.join(',') + '\n';
    
    Array.from(serviceMap.entries())
        .sort((a, b) => b[1].count - a[1].count)
        .forEach(([service, data]) => {
            const hosts = Array.from(data.hosts).join(';');
            const row = [
                `"${service}"`,
                `"${data.count}"`,
                `"${hosts}"`
            ];
            csv += row.join(',') + '\n';
        });
    
    return csv;
}

// Export up hosts table as CSV
function exportUpHostsAsCSV() {
    if (!window.scanData || !window.scanData.upHosts) return '';
    
    const headers = ['IP', 'Reason'];
    let csv = headers.join(',') + '\n';
    
    Object.entries(window.scanData.upHosts).forEach(([ip, reason]) => {
        const row = [
            `"${ip}"`,
            `"${reason}"`
        ];
        csv += row.join(',') + '\n';
    });
    
    return csv;
}

// Download CSV file
function downloadCSV(csvContent, filename) {
    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const link = document.createElement('a');
    
    if (link.download !== undefined) {
        const url = URL.createObjectURL(blob);
        link.setAttribute('href', url);
        link.setAttribute('download', filename);
        link.style.visibility = 'hidden';
        document.body.appendChild(link);
        link.click();
        document.body.removeChild(link);
        URL.revokeObjectURL(url);
    } else {
        showError('CSV download not supported in this browser');
    }
}

// Copy to clipboard functionality
function copyToClipboard(text, successMessage = 'Copied to clipboard!') {
    if (navigator.clipboard && window.isSecureContext) {
        // Use modern clipboard API
        navigator.clipboard.writeText(text).then(() => {
            showCopySuccess(successMessage);
        }).catch(err => {
            console.error('Failed to copy: ', err);
            fallbackCopyToClipboard(text, successMessage);
        });
    } else {
        // Fallback for older browsers
        fallbackCopyToClipboard(text, successMessage);
    }
}

// Fallback copy method for older browsers
function fallbackCopyToClipboard(text, successMessage) {
    const textArea = document.createElement('textarea');
    textArea.value = text;
    textArea.style.position = 'fixed';
    textArea.style.top = '0';
    textArea.style.left = '0';
    textArea.style.width = '2em';
    textArea.style.height = '2em';
    textArea.style.padding = '0';
    textArea.style.border = 'none';
    textArea.style.outline = 'none';
    textArea.style.boxShadow = 'none';
    textArea.style.background = 'transparent';
    document.body.appendChild(textArea);
    textArea.focus();
    textArea.select();
    
    try {
        const successful = document.execCommand('copy');
        if (successful) {
            showCopySuccess(successMessage);
        } else {
            showError('Failed to copy to clipboard');
        }
    } catch (err) {
        console.error('Fallback copy failed: ', err);
        showError('Copy to clipboard not supported');
    } finally {
        document.body.removeChild(textArea);
    }
}

// Show copy success message
function showCopySuccess(message) {
    // Create temporary success indicator
    const successDiv = document.createElement('div');
    successDiv.className = 'copy-success';
    successDiv.textContent = message;
    successDiv.style.cssText = `
        position: fixed;
        top: 20px;
        right: 20px;
        background-color: #2ecc71;
        color: white;
        padding: 10px 15px;
        border-radius: 5px;
        z-index: 2000;
        font-size: 0.9rem;
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.15);
        transform: translateX(100%);
        transition: transform 0.3s ease;
    `;
    
    document.body.appendChild(successDiv);
    
    // Animate in
    setTimeout(() => {
        successDiv.style.transform = 'translateX(0)';
    }, 10);
    
    // Remove after 2 seconds
    setTimeout(() => {
        successDiv.style.transform = 'translateX(100%)';
        setTimeout(() => {
            if (successDiv.parentNode) {
                document.body.removeChild(successDiv);
            }
        }, 300);
    }, 2000);
}

// Check for File API support
if (window.File && window.FileReader && window.FileList && window.Blob) {
    console.log('File APIs are supported');
} else {
    console.error('The File APIs are not fully supported in this browser.');
    showError('Your browser does not fully support the necessary file features. Please use a modern browser.');
}
