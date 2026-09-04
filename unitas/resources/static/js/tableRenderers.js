// Table rendering functions

// A copy icon that does not depend on emoji fonts and stays out of exported
// text (an aria-label carries the meaning instead of a glyph).
function createCopyButton(title, value, message) {
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'copy-btn';
    button.title = title;
    button.setAttribute('aria-label', title);
    button.innerHTML =
        '<svg viewBox="0 0 16 16" width="12" height="12" aria-hidden="true" focusable="false">' +
        '<rect x="5.5" y="5.5" width="8" height="9" rx="1.5" fill="none" stroke="currentColor"></rect>' +
        '<path d="M10.5 3.5h-8v9" fill="none" stroke="currentColor"></path></svg>';
    button.onclick = (e) => {
        e.stopPropagation();
        copyToClipboard(value, message);
    };
    return button;
}
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

    scanData.hosts.slice().sort((a, b) => compareIps(a.ip, b.ip)).forEach(host => {
        const row = document.createElement('tr');

        const ipCell = document.createElement('td');
        ipCell.className = 'ip-cell';
        ipCell.title = `IP Address: ${host.ip}${host.mac_address ? '\nMAC: ' + host.mac_address : ''}${host.vendor ? '\nVendor: ' + host.vendor : ''}`;
        
        const ipContainer = document.createElement('div');
        ipContainer.className = 'ip-container';
        
        const ipText = document.createElement('span');
        ipText.textContent = host.ip;
        ipContainer.appendChild(ipText);
        
        ipContainer.appendChild(
            createCopyButton('Copy IP address', host.ip, 'IP address copied!')
        );
        
        ipCell.appendChild(ipContainer);
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

            // Create detailed tooltip
            let tooltipText = `Port: ${port.port}/${port.protocol}\nService: ${port.service}`;
            if (port.comment) tooltipText += `\nComment: ${port.comment}`;
            if (port.state) tooltipText += `\nState: ${port.state}`;
            if (port.sources && port.sources.length > 0) {
                tooltipText += `\nDetected by: ${port.sources.map(s => s.type).join(', ')}`;
            }

            portItem.innerHTML = portText;
            portItem.title = tooltipText;
            portItem.className = 'port-item';
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
        const byIp = compareIps(a.ip, b.ip);
        if (byIp !== 0) return byIp;
        return parseInt(a.port) - parseInt(b.port);
    }).forEach(port => {
        const row = document.createElement('tr');

        const ipCell = document.createElement('td');
        ipCell.className = 'ip-cell';
        
        const ipContainer = document.createElement('div');
        ipContainer.className = 'ip-container';
        
        const ipText = document.createElement('span');
        ipText.textContent = port.ip;
        ipContainer.appendChild(ipText);
        
        ipContainer.appendChild(
            createCopyButton('Copy IP address', port.ip, 'IP address copied!')
        );
        
        ipCell.appendChild(ipContainer);
        row.appendChild(ipCell);

        const hostnameCell = document.createElement('td');
        hostnameCell.textContent = port.hostname || '-';
        row.appendChild(hostnameCell);

        const portCell = document.createElement('td');
        portCell.className = 'port-cell';
        
        const portContainer = document.createElement('div');
        portContainer.className = 'port-container';
        
        const portText = document.createElement('span');
        portText.textContent = port.port;
        portContainer.appendChild(portText);
        
        portContainer.appendChild(
            createCopyButton('Copy port number', port.port, 'Port number copied!')
        );
        
        portCell.appendChild(portContainer);
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

        // Status and comment are editable; the filters, the sort and the
        // exports read the row dataset, not these controls.
        row.dataset.ip = port.ip;
        row.dataset.port = port.port;
        row.dataset.protocol = port.protocol;
        row.dataset.service = port.service;
        row.dataset.state = effectiveState(port.ip, port);
        row.dataset.comment = effectiveComment(port.ip, port);
        row.dataset.tls = (port.tls || (port.comment || '').includes('TLS')) ? '1' : '';

        row.appendChild(createStateCell(port));
        row.appendChild(createCommentCell(port));

        portsTable.appendChild(row);
    });
}

const PORT_STATES = ['TBD', 'Done'];

function createStateCell(port) {
    const cell = document.createElement('td');
    const select = document.createElement('select');
    select.className = 'state-select';
    select.setAttribute('aria-label', `Status of ${port.ip} port ${port.port}`);

    const current = effectiveState(port.ip, port);
    const options = PORT_STATES.includes(current) ? PORT_STATES : PORT_STATES.concat(current);

    options.forEach(state => {
        const option = document.createElement('option');
        option.value = state;
        option.textContent = state;
        select.appendChild(option);
    });
    select.value = current;

    select.classList.toggle('edited', getPortEdit(port.ip, port) !== null);

    select.addEventListener('change', () => {
        setPortEdit(port.ip, port, { state: select.value });
        const row = cell.closest('tr');
        if (row) row.dataset.state = select.value;
        select.classList.toggle('edited', getPortEdit(port.ip, port) !== null);
        applyUiFilters();
    });

    cell.appendChild(select);
    return cell;
}

function createCommentCell(port) {
    const cell = document.createElement('td');
    cell.className = 'comment-cell';
    const current = effectiveComment(port.ip, port);

    // only badge TLS when the comment does not already say so
    if (port.tls && !current.includes('TLS')) {
        const badge = document.createElement('span');
        badge.className = 'badge badge-tls';
        badge.textContent = 'TLS';
        cell.appendChild(badge);
    }

    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'comment-input';
    input.value = current;
    input.placeholder = 'note';
    input.setAttribute('aria-label', `Comment for ${port.ip} port ${port.port}`);
    input.classList.toggle('edited', getPortEdit(port.ip, port) !== null);

    const commit = () => {
        setPortEdit(port.ip, port, { comment: input.value });
        const row = cell.closest('tr');
        if (row) row.dataset.comment = input.value;
        input.classList.toggle('edited', getPortEdit(port.ip, port) !== null);
        applyUiFilters();
    };

    input.addEventListener('change', commit);
    input.addEventListener('keydown', event => {
        if (event.key === 'Enter') {
            event.preventDefault();
            input.blur();
        }
    });

    cell.appendChild(input);
    return cell;
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

// Search and status filtering live in ui.js, which applies both criteria in a
// single pass (filterTables / filterPortsTableByStatus).

