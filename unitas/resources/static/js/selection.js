// Batch triage.
//
// Marking ports one click at a time is the slow part of working through a
// scan: fifty SMB ports on one subnet are one decision, not fifty. The Ports
// and Hosts tables get a select column with shift-click ranges and a toolbar
// that applies one state to everything selected -- against a live workspace
// that is one request, not one per row.

const SELECTION_TABLES = {
    'ports-table': { bar: 'ports-batch', count: 'ports-batch-count', unit: 'port' },
    'hosts-table': { bar: 'hosts-batch', count: 'hosts-batch-count', unit: 'host' }
};

// per table: the row a shift-click extends from
const selectionAnchors = {};

function selectableRows(table) {
    const body = table.tBodies[0];
    if (!body) return [];
    return Array.from(body.rows).filter(
        row => row.style.display !== 'none' && row.dataset.search !== undefined
    );
}

function selectedRows(table) {
    return selectableRows(table).filter(row => {
        const box = row.querySelector('[data-select-row]');
        return box && box.checked;
    });
}

function setRowSelected(row, selected) {
    const box = row.querySelector('[data-select-row]');
    if (!box) return;
    box.checked = selected;
    row.classList.toggle('row-selected', selected);
}

function clearSelection(table) {
    selectableRows(table).forEach(row => setRowSelected(row, false));
    updateSelectionBar(table);
}

function updateSelectionBar(table) {
    const config = SELECTION_TABLES[table.id];
    if (!config) return;

    const rows = selectableRows(table);
    const chosen = rows.filter(row => {
        const box = row.querySelector('[data-select-row]');
        return box && box.checked;
    });

    const bar = document.getElementById(config.bar);
    if (bar) bar.classList.toggle('hidden', chosen.length === 0);

    const label = document.getElementById(config.count);
    if (label) {
        label.textContent = `${chosen.length} ${config.unit}${chosen.length === 1 ? '' : 's'} selected`;
    }

    const all = table.querySelector('thead [data-select-all]');
    if (all) {
        all.checked = rows.length > 0 && chosen.length === rows.length;
        all.indeterminate = chosen.length > 0 && chosen.length < rows.length;
    }
}

// Shift-click selects the run between the last click and this one, which is
// what makes a subnet or a service block one gesture.
function handleSelectClick(table, box, shiftKey) {
    const row = box.closest('tr');
    row.classList.toggle('row-selected', box.checked);

    const rows = selectableRows(table);
    const anchor = selectionAnchors[table.id];
    const from = anchor ? rows.indexOf(anchor) : -1;
    const to = rows.indexOf(row);

    if (shiftKey && from !== -1 && to !== -1) {
        const start = Math.min(from, to);
        const end = Math.max(from, to);
        for (let i = start; i <= end; i++) setRowSelected(rows[i], box.checked);
    }

    selectionAnchors[table.id] = row;
    updateSelectionBar(table);
}

// ------------------------------------------------------------------ applying

function portForRow(row) {
    const host = (window.scanData.hosts || []).find(h => h.ip === row.dataset.ip);
    if (!host) return null;
    return host.ports.find(
        p => p.port === row.dataset.port && p.protocol === row.dataset.protocol
    ) || null;
}

function markPortRow(row, state) {
    const port = portForRow(row);
    if (!port) return false;

    setPortEdit(row.dataset.ip, port, { state: state });
    row.dataset.state = state;
    const button = row.querySelector('[data-state-toggle]');
    if (button) {
        button.textContent = state;
        button.classList.toggle('edited', getPortEdit(row.dataset.ip, port) !== null);
    }
    refreshRowSearch(row);
    refilterRow(document.getElementById('ports-table'), row);
    return true;
}

// A host is one edit against a live workspace; without one it falls back to
// the ports it has, which is what the localStorage overlay can express.
function markHostState(ip, state) {
    if (typeof workspaceSetHostState === 'function' && workspaceEnabled()) {
        workspaceSetHostState(ip, state);
    } else {
        const host = (window.scanData.hosts || []).find(h => h.ip === ip);
        if (!host) return;
        host.ports.forEach(port => setPortEdit(ip, port, { state: state }));
    }

    // the ports table shows the same ports, keep it honest
    const portsTable = document.getElementById('ports-table');
    if (!portsTable || !portsTable.tBodies[0]) return;
    Array.from(portsTable.tBodies[0].rows)
        .filter(row => row.dataset.ip === ip && row.dataset.search !== undefined)
        .forEach(row => markPortRow(row, state));
}

function applyBatchState(table, state) {
    const rows = selectedRows(table);
    if (rows.length === 0) return;

    if (table.id === 'ports-table') {
        const marked = rows.filter(row => markPortRow(row, state)).length;
        showToast(`${marked} port${marked === 1 ? '' : 's'} marked ${state}`);
    } else {
        rows.forEach(row => markHostState(row.dataset.ip, state));
        showToast(`${rows.length} host${rows.length === 1 ? '' : 's'} marked ${state}`);
    }

    clearSelection(table);
    updateEditIndicator();
}

// --------------------------------------------------------------------- setup

function setupSelection() {
    Object.keys(SELECTION_TABLES).forEach(tableId => {
        const table = document.getElementById(tableId);
        if (!table) return;

        table.addEventListener('click', event => {
            const box = event.target.closest('[data-select-row]');
            if (box) {
                handleSelectClick(table, box, event.shiftKey);
                return;
            }

            const all = event.target.closest('[data-select-all]');
            if (all) {
                selectableRows(table).forEach(row => setRowSelected(row, all.checked));
                selectionAnchors[table.id] = null;
                updateSelectionBar(table);
            }
        });

        const config = SELECTION_TABLES[tableId];
        const bar = document.getElementById(config.bar);
        if (!bar) return;

        bar.addEventListener('click', event => {
            const button = event.target.closest('button');
            if (!button) return;
            if (button.dataset.clear !== undefined) {
                clearSelection(table);
                return;
            }
            if (button.dataset.mark) applyBatchState(table, button.dataset.mark);
        });
    });
}

// A re-render or a filter change moves the ground under a selection. A row the
// filter just hid must not stay selected: it would come back checked when the
// filter is cleared, and "mark selected" would then cover rows the tester never
// saw.
function refreshSelections() {
    Object.keys(SELECTION_TABLES).forEach(tableId => {
        const table = document.getElementById(tableId);
        if (!table || !table.tBodies[0]) return;

        for (const row of table.tBodies[0].rows) {
            if (row.style.display !== 'none') continue;
            const box = row.querySelector('[data-select-row]');
            if (box && box.checked) setRowSelected(row, false);
        }

        const anchor = selectionAnchors[tableId];
        if (anchor && (!anchor.parentNode || anchor.style.display === 'none')) {
            selectionAnchors[tableId] = null;
        }
        updateSelectionBar(table);
    });
}

// ---------------------------------------------------------------- keyboard
//
// Working a list of ports is a two handed job: the mouse to read, the keyboard
// to mark. j/k move, x selects, d/p/u set a state (on the selection when there
// is one, otherwise on the row under the cursor) and n jumps into the note.
// "t" is taken by the theme toggle, so TBD is "u", as in untouched.

const TRIAGE_KEYS = { d: 'Done', p: 'In progress', u: 'TBD' };

function triageTable() {
    const viewId = activeViewId();
    if (viewId === 'ports-view') return document.getElementById('ports-table');
    if (viewId === 'hosts-view') return document.getElementById('hosts-table');
    return null;
}

function cursorRow(table) {
    const rows = selectableRows(table);
    if (rows.length === 0) return null;
    const current = rows.find(row => row.classList.contains('row-cursor'));
    return current || null;
}

function moveCursor(table, step) {
    const rows = selectableRows(table);
    if (rows.length === 0) return;

    const current = cursorRow(table);
    let index = current ? rows.indexOf(current) + step : (step > 0 ? 0 : rows.length - 1);
    index = Math.max(0, Math.min(rows.length - 1, index));

    if (current) current.classList.remove('row-cursor');
    const row = rows[index];
    row.classList.add('row-cursor');
    row.scrollIntoView({ block: 'nearest' });
}

function triageTargets(table) {
    const chosen = selectedRows(table);
    if (chosen.length) return chosen;
    const current = cursorRow(table);
    return current ? [current] : [];
}

function applyKeyboardState(table, state) {
    const rows = triageTargets(table);
    if (rows.length === 0) return;

    if (table.id === 'ports-table') {
        rows.forEach(row => markPortRow(row, state));
    } else {
        rows.forEach(row => markHostState(row.dataset.ip, state));
    }
    showToast(`${rows.length} row${rows.length === 1 ? '' : 's'} marked ${state}`);

    clearSelection(table);
    updateEditIndicator();
}

function setupTriageKeyboard() {
    document.addEventListener('keydown', event => {
        if (event.ctrlKey || event.metaKey || event.altKey) return;
        const tag = event.target.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;

        const table = triageTable();
        if (!table) return;

        if (event.key === 'j' || event.key === 'ArrowDown') {
            event.preventDefault();
            moveCursor(table, 1);
            return;
        }
        if (event.key === 'k' || event.key === 'ArrowUp') {
            event.preventDefault();
            moveCursor(table, -1);
            return;
        }

        const row = cursorRow(table);

        if (event.key === 'x') {
            event.preventDefault();
            if (!row) return;
            const box = row.querySelector('[data-select-row]');
            if (!box) return;
            box.checked = !box.checked;
            handleSelectClick(table, box, event.shiftKey);
            return;
        }

        if (event.key === 'n') {
            if (!row) return;
            const input = row.querySelector('[data-comment-input]');
            if (!input) return;
            event.preventDefault();
            input.focus();
            input.select();
            return;
        }

        if (event.key === 'g' && typeof cycleGroupMode === 'function') {
            event.preventDefault();
            cycleGroupMode();
            return;
        }

        if (TRIAGE_KEYS[event.key]) {
            event.preventDefault();
            applyKeyboardState(table, TRIAGE_KEYS[event.key]);
        }
    });
}

document.addEventListener('DOMContentLoaded', function () {
    setupSelection();
    setupTriageKeyboard();
});
