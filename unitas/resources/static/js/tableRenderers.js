// Table rendering functions
function populateTables() {
    if (!scanData) return;

    populateHostsTable();
    populatePortsTable();
    populateServicesTable();
    populateUpHostsTable();
}

function populateHostsTable() {
    const hostsTable = document.querySelector('#hosts-table tbody');
    hostsTable.innerHTML = '';

    if (scanData.hosts.length === 0) {
        renderEmptyTableMessage(hostsTable, 5, 'No hosts with open ports found.');
        return;
    }

    scanData.hosts.sort((a, b) => {
        // Sort by IP address
        const ipA = a.ip.split('.').map(num => parseInt(num.padStart(3, '0'))).join('');
        const ipB = b.ip.split('.').map(num => parseInt(num.padStart(3, '0'))).join('');
        return ipA.localeCompare(ipB);
    }).forEach(host => {
        const row = document.createElement('tr');

        const ipCell = document.createElement('td');
        ipCell.textContent = host.ip;
        row.appendChild(ipCell);

        const hostnameCell = document.createElement('td');
        hostnameCell.textContent = host.hostname || '-';
        row.appendChild(hostnameCell);

        // Add MAC address cell
        const macCell = document.createElement('td');
        macCell.textContent = host.mac_address || '-';
        row.appendChild(macCell);

        // Add vendor cell
        const vendorCell = document.createElement('td');
        vendorCell.textContent = host.vendor || '-';
        row.appendChild(vendorCell);

        const portsCell = document.createElement('td');
        const portsList = document.createElement('ul');
        portsList.className = 'port-list';

        host.ports.sort((a, b) => parseInt(a.port) - parseInt(b.port)).forEach(port => {
            const portItem = document.createElement('li');
            let portText = `${port.port}/${port.protocol} (${port.service})`;

            if (port.service.includes('?') || port.uncertain) {
                portText += ' <span class="badge badge-uncertain">?</span>';
            }

            if (port.comment.includes('TLS') || port.tls) {
                portText += ' <span class="badge badge-tls">TLS</span>';
            }

            portItem.innerHTML = portText;
            portsList.appendChild(portItem);
        });

        portsCell.appendChild(portsList);
        row.appendChild(portsCell);

        hostsTable.appendChild(row);
    });
}

function populatePortsTable() {
    const portsTable = document.querySelector('#ports-table tbody');
    portsTable.innerHTML = '';

    if (scanData.hosts.length === 0 || !scanData.hosts.some(host => host.ports.length > 0)) {
        renderEmptyTableMessage(portsTable, 7, 'No open ports found.');
        return;
    }

    const allPorts = [];

    scanData.hosts.forEach(host => {
        host.ports.forEach(port => {
            allPorts.push({
                ip: host.ip,
                hostname: host.hostname,
                ...port
            });
        });
    });

    allPorts.sort((a, b) => {
        // Sort by IP, then port number
        const ipA = a.ip.split('.').map(num => parseInt(num.padStart(3, '0'))).join('');
        const ipB = b.ip.split('.').map(num => parseInt(num.padStart(3, '0'))).join('');

        if (ipA !== ipB) return ipA.localeCompare(ipB);
        return parseInt(a.port) - parseInt(b.port);
    }).forEach(port => {
        const row = document.createElement('tr');

        const ipCell = document.createElement('td');
        ipCell.textContent = port.ip;
        row.appendChild(ipCell);

        const hostnameCell = document.createElement('td');
        hostnameCell.textContent = port.hostname || '-';
        row.appendChild(hostnameCell);

        const portCell = document.createElement('td');
        portCell.textContent = port.port;
        row.appendChild(portCell);

        const protocolCell = document.createElement('td');
        protocolCell.textContent = port.protocol;
        row.appendChild(protocolCell);

        const serviceCell = document.createElement('td');
        if (port.service.includes('?') || port.uncertain) {
            serviceCell.innerHTML = `${port.service.replace('?', '')} <span class="badge badge-uncertain">?</span>`;
        } else {
            serviceCell.textContent = port.service;
        }
        row.appendChild(serviceCell);

        const stateCell = document.createElement('td');
        stateCell.textContent = port.state || 'TBD';
        row.appendChild(stateCell);

        const commentCell = document.createElement('td');
        if (port.comment && port.comment.includes('TLS') || port.tls) {
            commentCell.innerHTML = `${port.comment ? port.comment.replace('TLS', '') : ''} <span class="badge badge-tls">TLS</span>`;
        } else {
            commentCell.textContent = port.comment || '';
        }
        row.appendChild(commentCell);

        portsTable.appendChild(row);
    });
}

function populateServicesTable() {
    const servicesTable = document.querySelector('#services-table tbody');
    servicesTable.innerHTML = '';

    if (scanData.hosts.length === 0 || !scanData.hosts.some(host => host.ports.length > 0)) {
        renderEmptyTableMessage(servicesTable, 3, 'No services found.');
        return;
    }

    // Group by service
    const serviceGroups = {};

    scanData.hosts.forEach(host => {
        host.ports.forEach(port => {
            const cleanService = port.service.replace('?', '');
            if (!serviceGroups[cleanService]) {
                serviceGroups[cleanService] = {
                    count: 0,
                    hosts: new Set()
                };
            }
            serviceGroups[cleanService].count++;
            serviceGroups[cleanService].hosts.add(host.ip);
        });
    });

    Object.entries(serviceGroups)
        .sort((a, b) => b[1].count - a[1].count)
        .forEach(([service, data]) => {
            const row = document.createElement('tr');

            const serviceCell = document.createElement('td');
            serviceCell.textContent = service;
            row.appendChild(serviceCell);

            const countCell = document.createElement('td');
            countCell.textContent = data.count;
            row.appendChild(countCell);

            const hostsCell = document.createElement('td');
            hostsCell.textContent = Array.from(data.hosts).join(', ');
            row.appendChild(hostsCell);

            servicesTable.appendChild(row);
        });
}

function populateUpHostsTable() {
    const upHostsTable = document.querySelector('#up-hosts-table tbody');
    upHostsTable.innerHTML = '';

    if (!scanData.hostsUp || scanData.hostsUp.length === 0) {
        renderEmptyTableMessage(upHostsTable, 2, 'No hosts that are up without open ports.');
        return;
    }

    scanData.hostsUp.sort((a, b) => {
        const ipA = a.ip.split('.').map(num => parseInt(num.padStart(3, '0'))).join('');
        const ipB = b.ip.split('.').map(num => parseInt(num.padStart(3, '0'))).join('');
        return ipA.localeCompare(ipB);
    }).forEach(host => {
        const row = document.createElement('tr');

        const ipCell = document.createElement('td');
        ipCell.textContent = host.ip;
        row.appendChild(ipCell);

        const reasonCell = document.createElement('td');
        reasonCell.textContent = host.reason;
        row.appendChild(reasonCell);

        upHostsTable.appendChild(row);
    });
}

function renderEmptyTableMessage(tableBody, colSpan, message) {
    const row = document.createElement('tr');
    const cell = document.createElement('td');
    cell.colSpan = colSpan;
    cell.className = 'empty-message';
    cell.textContent = message;
    row.appendChild(cell);
    tableBody.appendChild(row);
}

// Search functionality
function filterTables(searchTerm) {
    // Filter hosts table
    filterTable('#hosts-table tbody tr', searchTerm);

    // Filter ports table
    filterTable('#ports-table tbody tr', searchTerm);

    // Filter services table
    filterTable('#services-table tbody tr', searchTerm);

    // Filter up hosts table
    filterTable('#up-hosts-table tbody tr', searchTerm);
}

function filterTable(selector, searchTerm) {
    const rows = document.querySelectorAll(selector);
    rows.forEach(row => {
        const text = row.textContent.toLowerCase();
        row.style.display = text.includes(searchTerm) ? '' : 'none';
    });
}

// Filter buttons functionality
function filterPortsTableByStatus(status) {
    const rows = document.querySelectorAll('#ports-table tbody tr');

    rows.forEach(row => {
        if (status === 'all') {
            row.style.display = '';
        } else {
            const rowStatus = row.querySelector('td:nth-child(6)').textContent.toLowerCase();
            row.style.display = rowStatus === status ? '' : 'none';
        }
    });
}

