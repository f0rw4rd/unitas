// Create this as auto-loader-fix.js and replace the existing auto-loader.js
document.addEventListener('DOMContentLoaded', function () {
    console.log("Auto-loader started");

    // Add debug output to the page
    const debugContainer = document.createElement('div');
    debugContainer.id = 'debug-output';
    debugContainer.style.position = 'fixed';
    debugContainer.style.bottom = '10px';
    debugContainer.style.left = '10px';
    debugContainer.style.backgroundColor = 'rgba(0,0,0,0.7)';
    debugContainer.style.color = 'white';
    debugContainer.style.padding = '10px';
    debugContainer.style.borderRadius = '5px';
    debugContainer.style.zIndex = '9999';
    debugContainer.style.maxHeight = '200px';
    debugContainer.style.overflow = 'auto';
    debugContainer.style.maxWidth = '80%';
    debugContainer.style.display = 'none'; // Initially hidden
    document.body.appendChild(debugContainer);

    // Add toggle button for debug panel
    const debugToggle = document.createElement('button');
    debugToggle.textContent = 'Show Debug Info';
    debugToggle.style.position = 'fixed';
    debugToggle.style.bottom = '10px';
    debugToggle.style.left = '10px';
    debugToggle.style.zIndex = '10000';
    document.body.appendChild(debugToggle);

    function logDebug(message) {
        console.log(message);
        const debugOutput = document.getElementById('debug-output');
        if (debugOutput) {
            const logLine = document.createElement('div');
            logLine.textContent = message;
            debugOutput.appendChild(logLine);
            debugOutput.scrollTop = debugOutput.scrollHeight;
        }
    }

    // Fix for setupEventHandlers reference
    if (typeof setupEventHandlers !== 'function') {
        logDebug("Warning: setupEventHandlers not found, creating empty function");
        window.setupEventHandlers = function () {
            logDebug("Empty setupEventHandlers called");
        };
    }

    // Make sure window.scanData is in global scope
    window.window.scanData = null;

    // Patch the validateAndDisplayData function to add more debugging
    const originalValidateAndDisplayData = window.validateAndDisplayData;
    window.validateAndDisplayData = function (data) {
        logDebug("validateAndDisplayData called with data");

        // Basic validation check
        if (!data) {
            logDebug("ERROR: Data is null or undefined");
            showError('Data is empty or invalid');
            hideLoading();
            return;
        }

        if (!data.hosts || !Array.isArray(data.hosts)) {
            logDebug(`ERROR: Invalid data format. hosts property: ${typeof data.hosts}`);
            if (data.hosts) {
                logDebug(`hosts is not an array: ${typeof data.hosts}`);
            }
            logDebug(`Data structure: ${JSON.stringify(Object.keys(data))}`);
            showError('Invalid data format: Missing hosts array');
            hideLoading();
            return;
        }

        logDebug(`Data looks valid. Found ${data.hosts.length} hosts and ${data.hostsUp ? data.hostsUp.length : 0} hosts up`);

        // Make sure window.scanData is globally available
        window.window.scanData = data;

        try {
            // Switch views
            document.getElementById('initial-screen').classList.add('hidden');
            document.getElementById('data-view').classList.remove('hidden');
            document.getElementById('error-message').classList.add('hidden');

            logDebug("View switched to data view");

            // Display scan info
            if (data.metadata) {
                document.getElementById('scan-date').textContent = `Generated: ${data.metadata.generated || 'Unknown'}`;
                document.getElementById('scan-version').textContent = `Unitas ${data.metadata.version || 'Unknown'}`;
                logDebug("Metadata displayed");
            } else {
                document.getElementById('scan-date').textContent = 'Generated: Unknown';
                document.getElementById('scan-version').textContent = 'Unitas Unknown';
                logDebug("No metadata found");
            }

            // Initialize the visualization step by step with error catching
            try {
                logDebug("Starting updateStats...");
                updateStats();
                logDebug("Stats updated successfully");
            } catch (error) {
                logDebug(`ERROR in updateStats: ${error.message}`);
                console.error("Error in updateStats:", error);
            }

            try {
                logDebug("Starting populateTables...");
                populateTables();
                logDebug("Tables populated successfully");
            } catch (error) {
                logDebug(`ERROR in populateTables: ${error.message}`);
                console.error("Error in populateTables:", error);
            }

            try {
                logDebug("Starting populateServiceFilter...");
                populateServiceFilter();
                logDebug("Service filter populated successfully");
            } catch (error) {
                logDebug(`ERROR in populateServiceFilter: ${error.message}`);
                console.error("Error in populateServiceFilter:", error);
            }

            try {
                logDebug("Starting setupEventHandlers...");
                window.setupEventHandlers();
                logDebug("Event handlers set up successfully");
            } catch (error) {
                logDebug(`ERROR in setupEventHandlers: ${error.message}`);
                console.error("Error in setupEventHandlers:", error);
            }

            hideLoading();
            logDebug("Loading hidden, initialization complete");

        } catch (error) {
            logDebug(`CRITICAL ERROR in validateAndDisplayData: ${error.message}`);
            console.error("Critical error in validateAndDisplayData:", error);
            showError(`Error displaying data: ${error.message}`);
            hideLoading();
        }
    };

    // Auto-load the JSON data
    logDebug("Starting fetch of data.json");
    fetch('data.json')
        .then(response => {
            logDebug(`Fetch response status: ${response.status}`);
            if (!response.ok) {
                throw new Error('Network response was not ok');
            }
            return response.json();
        })
        .then(data => {
            logDebug(`Data loaded successfully, contains ${Object.keys(data).length} top-level keys`);

            // Store data globally
            window.window.scanData = data;

            // Call validation function
            validateAndDisplayData(data);
        })
        .catch(error => {
            logDebug(`ERROR loading data: ${error.message}`);
            console.error('Error loading data:', error);
            const errorMsg = document.getElementById('error-message');
            if (errorMsg) {
                errorMsg.textContent = `Error loading data: ${error.message}. Please try uploading manually.`;
                errorMsg.classList.remove('hidden');
            }
        });
});


// Function to ensure the UI is properly displayed
function fixUIDisplay() {
    console.log("Fixing UI display");

    // 1. Check if views are properly switched
    const dataView = document.getElementById('data-view');
    if (dataView) {
        dataView.classList.remove('hidden');
        console.log("Made data-view visible");
    }

    // 2. Force the active tab/view
    document.querySelectorAll('.nav-item').forEach(item => {
        item.classList.remove('active');
    });

    document.querySelectorAll('.view').forEach(view => {
        view.classList.remove('active');
    });

    // Make hosts view active as default
    const hostsNavItem = document.querySelector('.nav-item[data-view="hosts-view"]');
    if (hostsNavItem) {
        hostsNavItem.classList.add('active');
        console.log("Activated hosts-view nav item");
    }

    const hostsView = document.getElementById('hosts-view');
    if (hostsView) {
        hostsView.classList.add('active');
        console.log("Activated hosts-view");
    }

    // 3. Check if tables are populated
    const hostsTable = document.querySelector('#hosts-table tbody');
    console.log("Hosts table rows:", hostsTable ? hostsTable.children.length : 'table not found');

    // If table is empty but we have data, force repopulate
    if (hostsTable && hostsTable.children.length === 0 && window.window.scanData && window.window.scanData.hosts.length > 0) {
        console.log("Re-populating tables");
        window.populateTables();
    }

    // 4. Check if any tables have content
    const allTables = document.querySelectorAll('table tbody');
    let tablePopulated = false;

    allTables.forEach(table => {
        if (table.children.length > 0) {
            tablePopulated = true;
            console.log(`Table ${table.parentElement.id} has ${table.children.length} rows`);
        }
    });

    if (!tablePopulated) {
        console.log("No tables have content. Attempting manual population");

        // 5. Try manual population as a fallback
        if (window.window.scanData && window.window.scanData.hosts.length > 0) {
            const hostsTable = document.querySelector('#hosts-table tbody');
            if (hostsTable) {
                // Clear table
                hostsTable.innerHTML = '';

                // Manually add rows
                window.window.scanData.hosts.forEach(host => {
                    const row = document.createElement('tr');

                    const ipCell = document.createElement('td');
                    ipCell.textContent = host.ip;
                    row.appendChild(ipCell);

                    const hostnameCell = document.createElement('td');
                    hostnameCell.textContent = host.hostname || '-';
                    row.appendChild(hostnameCell);

                    const portsCell = document.createElement('td');
                    portsCell.textContent = `${host.ports.length} ports`;
                    row.appendChild(portsCell);

                    hostsTable.appendChild(row);
                });

                console.log("Manually populated hosts table");
            }
        }
    }

    // 6. Ensure the stats are updated
    updateStatsDisplay();
}

// Function to manually update stats
function updateStatsDisplay() {
    if (!window.window.scanData) return;

    document.getElementById('total-hosts').textContent = window.window.scanData.hosts.length;

    let totalPorts = 0;
    window.window.scanData.hosts.forEach(host => {
        totalPorts += host.ports.length;
    });
    document.getElementById('total-ports').textContent = totalPorts;

    document.getElementById('up-hosts').textContent = window.window.scanData.hostsUp ? window.window.scanData.hostsUp.length : 0;

    // Count unique services
    const services = new Set();
    window.window.scanData.hosts.forEach(host => {
        host.ports.forEach(port => {
            const cleanService = port.service.replace('?', '');
            services.add(cleanService);
        });
    });
    document.getElementById('services-count').textContent = services.size;

    console.log("Stats updated manually");
}

// Run the fix after a short delay to ensure everything is loaded
setTimeout(fixUIDisplay, 500);
