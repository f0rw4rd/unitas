// Main application initialization
document.addEventListener('DOMContentLoaded', function() {
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
    dropArea.addEventListener('drop', function(e) {
        const dt = e.dataTransfer;
        const files = dt.files;

        if (files.length === 1) {
            handleFile(files[0]);
        } else {
            showError('Please drop a single JSON file.');
        }
    }, false);

    // Handle file input
    fileInput.addEventListener('change', function() {
        if (this.files.length === 1) {
            handleFile(this.files[0]);
        } else {
            showError('Please select a single JSON file.');
        }
    });

    // Handle reload button
    reloadBtn.addEventListener('click', function() {
        initialScreen.classList.remove('hidden');
        dataView.classList.add('hidden');
        errorMessage.classList.add('hidden');
        fileInput.value = '';
        scanData = null;
        
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

    // Navigation
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            document.querySelectorAll('.nav-item').forEach(i => i.classList.remove('active'));
            document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));

            item.classList.add('active');
            const viewId = item.getAttribute('data-view');
            document.getElementById(viewId).classList.add('active');

            if (viewId === 'graph-view' && scanData) {
                if (!network) {
                    renderGraph();
                }
            }
        });
    });

    // Search functionality
    searchInput.addEventListener('input', function() {
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
    document.getElementById('node-size').addEventListener('input', function() {
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
        radio.addEventListener('change', function() {
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

            if (viewId === 'graph-view' && scanData) {
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
                scanData = data;
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
            scanData = data;
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
            scanData = data;
            validateAndDisplayData(data);
        })
        .catch(error => {
            console.error('Error loading data:', error);
            showError(`Error loading data: ${error.message}`);
            hideLoading();
        });
}

// Check for File API support
if (window.File && window.FileReader && window.FileList && window.Blob) {
    console.log('File APIs are supported');
} else {
    console.error('The File APIs are not fully supported in this browser.');
    showError('Your browser does not fully support the necessary file features. Please use a modern browser.');
}
