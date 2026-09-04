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
    });

    // Handle export markdown button
    exportMarkdownBtn.addEventListener('click', exportNetworkAsMarkdown);

    // Handle export CSV button
    const exportCsvBtn = document.getElementById('export-csv-btn');
    exportCsvBtn.addEventListener('click', exportCurrentViewAsCSV);

    // Triage: state.md export, edit reset and the target list menu
    document.getElementById('export-state-btn').addEventListener('click', exportStateMarkdown);
    document.getElementById('reset-edits-btn').addEventListener('click', function () {
        if (editCount() === 0) return;
        if (confirm(`Discard ${editCount()} edited port(s)?`)) {
            clearEdits();
            showToast('Edits discarded');
        }
    });
    setupCopyMenu();

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

    // Search functionality. Debounced: a filter pass walks every row of every
    // table, and input events are not coalesced, so typing a word used to queue
    // one full pass per character.
    let searchTimer = null;
    searchInput.addEventListener('input', function () {
        const searchTerm = this.value;
        clearTimeout(searchTimer);
        searchTimer = setTimeout(() => filterTables(searchTerm), 120);
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

    // Saved graph views survive a reload
    loadSavedViews();
    refreshSavedViewSelect();

    // Check for auto-load data from URL parameters
    checkForAutoLoadData();

    // Setup keyboard shortcuts
    setupKeyboardShortcuts();

    // Setup shortcuts panel toggle
    setupShortcutsPanel();

    // Setup table sorting
    setupTableSorting();

    // Delegated handlers for the editable status and comment cells
    setupPortsTableEditing();
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
    document.getElementById('load-view').addEventListener('click', loadSelectedView);
    document.getElementById('delete-view').addEventListener('click', deleteSelectedView);
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

            if (this.value === 'circular') {
                // vis has no circular layout, the nodes are placed by hand
                placeNodesInCircle();
                return;
            }

            // leaving the circular layout means physics has to come back
            if (!physicsEnabled) {
                network.setOptions({ physics: { enabled: true } });
                physicsEnabled = true;
                document.getElementById('toggle-physics').textContent = 'Disable Physics';
            }

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

function checkForAutoLoadData() {
    // Function to check for URL parameters to auto-load data
    const urlParams = new URLSearchParams(window.location.search);
    const dataUrl = urlParams.get('data');

    if (dataUrl) {
        tryLoadFromUrl(dataUrl);
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
        header.addEventListener('click', function () {
            const table = this.closest('table');
            const tbody = table.querySelector('tbody');
            const sortField = this.dataset.sort;
            const currentSort = this.classList.contains('sort-asc') ? 'asc' :
                this.classList.contains('sort-desc') ? 'desc' : null;

            // Remove sort classes from all headers in this table
            table.querySelectorAll('th.sortable').forEach(h => {
                h.classList.remove('sort-asc', 'sort-desc');
            });

            const newSort = currentSort === 'asc' ? 'desc' : 'asc';
            this.classList.add(newSort === 'asc' ? 'sort-asc' : 'sort-desc');

            // Decorate once, then sort primitives. Reading the cells inside the
            // comparator meant a querySelectorAll, a closest() and a textContent
            // per comparison, i.e. O(n log n) DOM queries for one click.
            const numeric = sortField === 'port' || sortField === 'count';
            const isIp = sortField === 'ip';
            const rows = [];
            for (const row of tbody.rows) {
                if (row === table._noMatchRow || row.querySelector('.empty-message')) continue;
                let key = getSortValue(row, sortField);
                if (numeric) {
                    key = parseInt(key, 10) || 0;
                } else if (isIp) {
                    key = ipSortKey(key);
                } else {
                    key = key.toLowerCase();
                }
                rows.push({ row, key });
            }

            const direction = newSort === 'asc' ? 1 : -1;
            rows.sort((a, b) => (a.key < b.key ? -direction : a.key > b.key ? direction : 0));

            // detach while re-ordering: moving rows inside a live table makes
            // the engine re-check the layout of the whole table each time
            const placeholder = document.createComment('sorting');
            tbody.replaceWith(placeholder);
            const fragment = document.createDocumentFragment();
            rows.forEach(entry => fragment.appendChild(entry.row));
            tbody.appendChild(fragment);
            placeholder.replaceWith(tbody);
        });
    });
}

const SORT_FIELDS = {
    'hosts-table': { ip: 0, hostname: 1, mac: 2, vendor: 3, ports: 4 },
    'ports-table': { ip: 0, hostname: 1, port: 2, protocol: 3, service: 4 },
    'services-table': { service: 0, count: 1, hosts: 2 },
    'up-hosts-table': { ip: 0, reason: 1 }
};

// Get sort value from table row
function getSortValue(row, field) {
    // the ports table keeps everything sortable on the row itself
    if (row.dataset[field] !== undefined) return row.dataset[field];
    if (field === 'status') return row.dataset.state || '';

    const fields = SORT_FIELDS[row.parentNode.parentNode.id];
    if (!fields || fields[field] === undefined) return '';
    const cell = row.cells[fields[field]];
    return cell ? cell.textContent.trim() : '';
}

// Comparable sort key for an address. `<<` would overflow into negative
// numbers for a first octet >= 128 and IPv6 has no numeric form here, so IPv4
// addresses become zero padded strings and everything else is compared as text
// behind them.
function ipSortKey(ip) {
    if (!ip || ip === '-') return '￿';
    const octets = ip.split('.');
    if (octets.length === 4 && octets.every(o => /^\d{1,3}$/.test(o))) {
        return '0' + octets.map(o => o.padStart(3, '0')).join('.');
    }
    return '1' + ip.toLowerCase();
}

function compareIps(a, b) {
    const keyA = ipSortKey(a);
    const keyB = ipSortKey(b);
    return keyA < keyB ? -1 : keyA > keyB ? 1 : 0;
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
