// Table rendering functions

// A copy icon that does not depend on emoji fonts and stays out of exported
// text (an aria-label carries the meaning instead of a glyph).
let copyButtonTemplate = null;

function createCopyButton(title, value, message) {
    if (copyButtonTemplate === null) {
        // built once and drawn by the stylesheet: an inline SVG here meant four
        // extra elements per row, and parsing its markup per row on top
        copyButtonTemplate = document.createElement('button');
        copyButtonTemplate.type = 'button';
        copyButtonTemplate.className = 'copy-btn';
    }

    const button = copyButtonTemplate.cloneNode(false);
    button.title = title;
    button.setAttribute('aria-label', title);
    button.dataset.copy = value;
    button.dataset.copyMessage = message;
    return button;
}

// One delegated listener instead of a closure per button
document.addEventListener('click', event => {
    const button = event.target.closest('.copy-btn');
    if (!button || button.dataset.copy === undefined) return;
    event.stopPropagation();
    copyToClipboard(button.dataset.copy, button.dataset.copyMessage);
});
function populateTables() {
    if (!scanData) return;

    populateHostsTable();
    populatePortsTable();
    populateServicesTable();
    populateUpHostsTable();

    // the rows the selection pointed at are gone
    if (typeof refreshSelections === 'function') refreshSelections();
}

function populateHostsTable() {
    const hostsTable = document.querySelector('#hosts-table tbody');
    hostsTable.innerHTML = '';
    hostsTable.parentNode._noMatchRow = null;

    if (scanData.hosts.length === 0) {
        renderEmptyTableMessage(hostsTable, 6, 'No hosts with open ports found.');
        return;
    }

    // built off-document, one insertion instead of one per host
    const fragment = document.createDocumentFragment();

    scanData.hosts.slice().sort((a, b) => compareIps(a.ip, b.ip)).forEach(host => {
        const row = document.createElement('tr');
        row.dataset.ip = host.ip;
        row.appendChild(selectCell());

        const ipCell = document.createElement('td');
        ipCell.className = 'ip-cell';
        ipCell.title = `IP Address: ${host.ip}${host.mac_address ? '\nMAC: ' + host.mac_address : ''}${host.vendor ? '\nVendor: ' + host.vendor : ''}`;
        ipCell.append(host.ip, createCopyButton('Copy IP address', host.ip, 'IP address copied!'));
        row.appendChild(ipCell);

        row.appendChild(textCell(host.hostname || '-'));
        row.appendChild(textCell(host.mac_address || '-', 'mac-cell'));
        row.appendChild(textCell(host.vendor || '-'));

        const portsCell = document.createElement('td');
        const portsList = document.createElement('ul');
        portsList.className = 'port-list';

        const searchParts = [host.ip, host.hostname, host.mac_address, host.vendor];

        host.ports.slice().sort((a, b) => parseInt(a.port) - parseInt(b.port)).forEach(port => {
            const portItem = document.createElement('li');
            portItem.className = 'port-item';
            const label = `${port.port}/${port.protocol} (${port.service})`;
            portItem.append(label);
            searchParts.push(label);

            if (port.service.includes('?') || port.uncertain) {
                portItem.appendChild(badge('badge-uncertain', '?'));
            }
            if (port.comment.includes('TLS') || port.tls) {
                portItem.appendChild(badge('badge-tls', 'TLS'));
            }

            let tooltipText = `Port: ${port.port}/${port.protocol}\nService: ${port.service}`;
            if (port.comment) tooltipText += `\nComment: ${port.comment}`;
            if (port.state) tooltipText += `\nState: ${port.state}`;
            if (port.sources && port.sources.length > 0) {
                tooltipText += `\nDetected by: ${port.sources.map(s => s.type).join(', ')}`;
            }
            portItem.title = tooltipText;

            portsList.appendChild(portItem);
        });

        portsCell.appendChild(portsList);
        row.appendChild(portsCell);

        // the filter reads this instead of walking the row on every keystroke
        row.dataset.search = searchParts.filter(Boolean).join(' ').toLowerCase();

        fragment.appendChild(row);
    });

    hostsTable.appendChild(fragment);
}

// The first cell of the triage tables: a checkbox the selection code reads,
// kept out of the row's search text and out of the CSV.
function selectCell() {
    const cell = document.createElement('td');
    cell.className = 'select-col';
    const box = document.createElement('input');
    box.type = 'checkbox';
    box.dataset.selectRow = '';
    box.setAttribute('aria-label', 'Select this row');
    cell.appendChild(box);
    return cell;
}

function textCell(text, className) {
    const cell = document.createElement('td');
    if (className) cell.className = className;
    cell.textContent = text;
    return cell;
}

function badge(className, text) {
    const span = document.createElement('span');
    span.className = `badge ${className}`;
    span.textContent = text;
    return span;
}

function populatePortsTable() {
    const portsTable = document.querySelector('#ports-table tbody');
    portsTable.innerHTML = '';
    portsTable.parentNode._noMatchRow = null;

    if (scanData.hosts.length === 0 || !scanData.hosts.some(host => host.ports.length > 0)) {
        renderEmptyTableMessage(portsTable, 8, 'No open ports found.');
        return;
    }

    const allPorts = [];
    scanData.hosts.forEach(host => {
        host.ports.forEach(port => {
            allPorts.push({ ip: host.ip, hostname: host.hostname, port: port });
        });
    });

    // decorate once: ipSortKey per comparison was most of the sort cost
    allPorts.forEach(entry => {
        entry.key = ipSortKey(entry.ip);
        entry.number = parseInt(entry.port.port, 10);
    });
    allPorts.sort((a, b) => (a.key < b.key ? -1 : a.key > b.key ? 1 : a.number - b.number));

    const fragment = document.createDocumentFragment();

    allPorts.forEach(entry => {
        const port = entry.port;
        const row = document.createElement('tr');

        const state = effectiveState(entry.ip, port);
        const comment = effectiveComment(entry.ip, port);
        const edited = getPortEdit(entry.ip, port) !== null;

        row.appendChild(selectCell());

        const ipCell = document.createElement('td');
        ipCell.className = 'ip-cell';
        ipCell.append(entry.ip, createCopyButton('Copy IP address', entry.ip, 'IP address copied!'));
        row.appendChild(ipCell);

        row.appendChild(textCell(entry.hostname || '-'));

        const portCell = document.createElement('td');
        portCell.className = 'port-cell';
        portCell.append(port.port, createCopyButton('Copy port number', port.port, 'Port number copied!'));
        row.appendChild(portCell);

        row.appendChild(textCell(port.protocol));

        const serviceCell = document.createElement('td');
        if (port.service.includes('?') || port.uncertain) {
            serviceCell.append(port.service.replace('?', ''), badge('badge-uncertain', '?'));
        } else {
            serviceCell.textContent = port.service;
        }
        row.appendChild(serviceCell);

        row.dataset.ip = entry.ip;
        row.dataset.hostname = entry.hostname || '';
        row.dataset.port = port.port;
        row.dataset.protocol = port.protocol;
        row.dataset.service = port.service;
        row.dataset.state = state;
        row.dataset.comment = comment;
        row.dataset.tls = (port.tls || (port.comment || '').includes('TLS')) ? '1' : '';
        row.dataset.search = [entry.ip, entry.hostname, port.port, port.protocol,
                              port.service, state, comment].filter(Boolean).join(' ').toLowerCase();

        row.appendChild(createStateCell(state, edited));
        row.appendChild(createCommentCell(port, comment, edited));

        fragment.appendChild(row);
    });

    portsTable.appendChild(fragment);
}

const PORT_STATES = ['TBD', 'In progress', 'Done'];

// A button rather than a <select>: the select was four elements per row for two
// words of text, and its <option> labels leaked into the row text so a search
// for "done" matched every row.
function createStateCell(state, edited) {
    const cell = document.createElement('td');
    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'state-toggle';
    button.dataset.stateToggle = '';
    button.textContent = state;
    button.title = 'Click to change the status';
    button.classList.toggle('edited', edited);
    cell.appendChild(button);
    return cell;
}

function nextPortState(current) {
    const index = PORT_STATES.indexOf(current);
    if (index === -1) return PORT_STATES[0];
    return PORT_STATES[(index + 1) % PORT_STATES.length];
}

function createCommentCell(port, comment, edited) {
    const cell = document.createElement('td');
    cell.className = 'comment-cell';

    // only badge TLS when the comment does not already say so
    if (port.tls && !comment.includes('TLS')) {
        cell.appendChild(badge('badge-tls', 'TLS'));
    }

    const input = document.createElement('input');
    input.type = 'text';
    input.className = 'comment-input';
    input.value = comment;
    input.placeholder = 'note';
    input.dataset.commentInput = '';
    input.classList.toggle('edited', edited);
    cell.appendChild(input);
    return cell;
}

// One set of delegated handlers for the whole table instead of two closures per
// row, and only the edited row is re-filtered.
function setupPortsTableEditing() {
    const table = document.getElementById('ports-table');
    if (!table) return;

    const portOf = row => {
        const host = (window.scanData.hosts || []).find(h => h.ip === row.dataset.ip);
        if (!host) return null;
        return host.ports.find(
            p => p.port === row.dataset.port && p.protocol === row.dataset.protocol
        ) || null;
    };

    table.addEventListener('click', event => {
        const button = event.target.closest('[data-state-toggle]');
        if (!button) return;
        const row = button.closest('tr');
        const port = portOf(row);
        if (!port) return;

        const state = nextPortState(button.textContent.trim());
        button.textContent = state;
        setPortEdit(row.dataset.ip, port, { state: state });
        row.dataset.state = state;
        refreshRowSearch(row);
        button.classList.toggle('edited', getPortEdit(row.dataset.ip, port) !== null);
        refilterRow(table, row);
    });

    const commit = input => {
        const row = input.closest('tr');
        const port = portOf(row);
        if (!port) return;
        setPortEdit(row.dataset.ip, port, { comment: input.value });
        row.dataset.comment = input.value;
        refreshRowSearch(row);
        input.classList.toggle('edited', getPortEdit(row.dataset.ip, port) !== null);
        refilterRow(table, row);
    };

    table.addEventListener('change', event => {
        if (event.target.dataset.commentInput !== undefined) commit(event.target);
    });

    table.addEventListener('keydown', event => {
        if (event.key === 'Enter' && event.target.dataset.commentInput !== undefined) {
            event.preventDefault();
            event.target.blur();
        }
    });
}

function refreshRowSearch(row) {
    row.dataset.search = [row.dataset.ip, row.dataset.hostname, row.dataset.port,
                          row.dataset.protocol, row.dataset.service, row.dataset.state,
                          row.dataset.comment].filter(Boolean).join(' ').toLowerCase();
}

function populateServicesTable() {
    const servicesTable = document.querySelector('#services-table tbody');
    servicesTable.innerHTML = '';
    servicesTable.parentNode._noMatchRow = null;

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

    const fragment = document.createDocumentFragment();

    Object.entries(serviceGroups)
        .sort((a, b) => b[1].count - a[1].count)
        .forEach(([service, data]) => {
            const row = document.createElement('tr');
            const hosts = Array.from(data.hosts).join(', ');

            row.appendChild(textCell(service));
            row.appendChild(textCell(String(data.count)));
            row.appendChild(textCell(hosts));

            row.dataset.service = service;
            row.dataset.count = String(data.count);
            row.dataset.search = `${service} ${hosts}`.toLowerCase();

            fragment.appendChild(row);
        });

    servicesTable.appendChild(fragment);
}

function populateUpHostsTable() {
    const upHostsTable = document.querySelector('#up-hosts-table tbody');
    upHostsTable.innerHTML = '';
    upHostsTable.parentNode._noMatchRow = null;

    if (!scanData.hostsUp || scanData.hostsUp.length === 0) {
        renderEmptyTableMessage(upHostsTable, 2, 'No hosts that are up without open ports.');
        return;
    }

    const fragment = document.createDocumentFragment();

    // the previous key ran parseInt over zero padded octets, which throws the
    // padding away again and ordered .100 before .21 before .9
    scanData.hostsUp
        .slice()
        .sort((a, b) => compareIps(a.ip, b.ip))
        .forEach(host => {
            const row = document.createElement('tr');
            row.appendChild(textCell(host.ip, 'ip-cell'));
            row.appendChild(textCell(host.reason));

            row.dataset.ip = host.ip;
            row.dataset.reason = host.reason;
            row.dataset.search = `${host.ip} ${host.reason}`.toLowerCase();

            fragment.appendChild(row);
        });

    upHostsTable.appendChild(fragment);
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

