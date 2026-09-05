// The worklist view.
//
// A flat list of 4000 ports is not a plan. Grouping the Ports view by service
// or by subnet turns it into one: "smb - 14 ports, 7 hosts, 3 done" is a piece
// of work with a size and an end, and the group can be collapsed once it is
// finished. The counts come from the same state the table shows, so they move
// with every mark.

const GROUP_MODES = {
    service: {
        label: 'service',
        key: row => (row.dataset.service || '').replace('?', '') || 'unknown'
    },
    subnet: {
        label: 'subnet',
        key: row => (typeof getSubnet === 'function' ? getSubnet(row.dataset.ip) : row.dataset.ip)
    }
};

let groupMode = 'none';
const collapsedGroups = new Set();

function groupingActive() {
    return groupMode !== 'none' && GROUP_MODES[groupMode] !== undefined;
}

function rowIsCollapsed(row) {
    return Boolean(row.dataset.group) && collapsedGroups.has(row.dataset.group);
}

// Re-orders the rows the renderer produced and inserts one header per group.
// The rows themselves are untouched, so every other feature -- the filters,
// the selection, the state cells -- keeps working on them.
function applyGrouping() {
    const table = document.getElementById('ports-table');
    if (!table || !table.tBodies[0]) return;
    const body = table.tBodies[0];

    Array.from(body.querySelectorAll('tr.group-row')).forEach(row => row.remove());

    const rows = Array.from(body.rows).filter(row => row.dataset.search !== undefined);
    if (!groupingActive()) {
        rows.forEach(row => delete row.dataset.group);
        collapsedGroups.clear();
        // put them back in the order the renderer wanted
        rows.forEach(row => body.appendChild(row));
        applyUiFilters();
        return;
    }

    const mode = GROUP_MODES[groupMode];
    const groups = new Map();
    rows.forEach(row => {
        const key = mode.key(row) || 'unknown';
        row.dataset.group = key;
        if (!groups.has(key)) groups.set(key, []);
        groups.get(key).push(row);
    });

    // biggest first: the long tail of one-off ports belongs at the bottom
    const ordered = Array.from(groups.entries()).sort((a, b) => {
        if (a[1].length !== b[1].length) return b[1].length - a[1].length;
        return a[0] < b[0] ? -1 : a[0] > b[0] ? 1 : 0;
    });

    const fragment = document.createDocumentFragment();
    ordered.forEach(([key, members]) => {
        fragment.appendChild(groupHeaderRow(key, table));
        members.forEach(row => fragment.appendChild(row));
    });
    body.appendChild(fragment);

    applyUiFilters();
}

function groupHeaderRow(key, table) {
    const row = document.createElement('tr');
    row.className = 'group-row';
    row.dataset.groupHeader = key;

    const cell = document.createElement('td');
    cell.colSpan = table.querySelectorAll('thead th').length || 1;

    const button = document.createElement('button');
    button.type = 'button';
    button.className = 'group-toggle';
    button.dataset.groupToggle = key;

    const caret = document.createElement('span');
    caret.className = 'group-caret';
    caret.textContent = collapsedGroups.has(key) ? '▸' : '▾';
    button.appendChild(caret);

    const name = document.createElement('span');
    name.className = 'group-name';
    name.textContent = key;
    button.appendChild(name);

    const counts = document.createElement('span');
    counts.className = 'group-counts';
    button.appendChild(counts);

    const progress = document.createElement('span');
    progress.className = 'group-progress';
    const bar = document.createElement('span');
    bar.className = 'group-progress-bar';
    progress.appendChild(bar);
    button.appendChild(progress);

    cell.appendChild(button);
    row.appendChild(cell);
    return row;
}

// Called after every filter pass: the headers describe what is on screen, and
// a group the filter emptied should not be left claiming rows.
function updateGroupHeaders(table) {
    if (!table || table.id !== 'ports-table' || !table.tBodies[0]) return;

    const headers = table.querySelectorAll('tr.group-row');
    if (headers.length === 0) return;

    const stats = new Map();
    for (const row of table.tBodies[0].rows) {
        if (row.dataset.search === undefined || !row.dataset.group) continue;
        if (row.dataset.filterMatch !== '1') continue;

        let entry = stats.get(row.dataset.group);
        if (!entry) {
            entry = { ports: 0, hosts: new Set(), done: 0 };
            stats.set(row.dataset.group, entry);
        }
        entry.ports += 1;
        entry.hosts.add(row.dataset.ip);
        if ((row.dataset.state || '').toLowerCase() === 'done') entry.done += 1;
    }

    headers.forEach(header => {
        const key = header.dataset.groupHeader;
        const entry = stats.get(key);

        if (!entry) {
            header.style.display = 'none';
            return;
        }
        header.style.display = '';

        const collapsed = collapsedGroups.has(key);
        header.querySelector('.group-caret').textContent = collapsed ? '▸' : '▾';
        header.querySelector('.group-counts').textContent =
            `${entry.ports} port${entry.ports === 1 ? '' : 's'}, ` +
            `${entry.hosts.size} host${entry.hosts.size === 1 ? '' : 's'}, ` +
            `${entry.done} done`;

        const percent = entry.ports ? Math.round((entry.done / entry.ports) * 100) : 0;
        header.querySelector('.group-progress-bar').style.width = `${percent}%`;
        header.classList.toggle('group-complete', entry.done === entry.ports);
    });
}

function toggleGroup(key) {
    if (collapsedGroups.has(key)) {
        collapsedGroups.delete(key);
    } else {
        collapsedGroups.add(key);
    }
    applyUiFilters();
}

function setGroupMode(mode) {
    groupMode = GROUP_MODES[mode] ? mode : 'none';
    collapsedGroups.clear();
    applyGrouping();
}

function cycleGroupMode() {
    const order = ['none', 'service', 'subnet'];
    const next = order[(order.indexOf(groupMode) + 1) % order.length];
    const select = document.getElementById('group-by');
    if (select) select.value = next;
    setGroupMode(next);
    showToast(next === 'none' ? 'Grouping off' : `Grouped by ${GROUP_MODES[next].label}`);
}

function setupGrouping() {
    const select = document.getElementById('group-by');
    if (select) {
        select.addEventListener('change', () => setGroupMode(select.value));
    }

    const table = document.getElementById('ports-table');
    if (!table) return;
    table.addEventListener('click', event => {
        const button = event.target.closest('[data-group-toggle]');
        if (button) toggleGroup(button.dataset.groupToggle);
    });
}

document.addEventListener('DOMContentLoaded', setupGrouping);
