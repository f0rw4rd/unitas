// Shell behaviour of the viewer: theme switching, combined table filtering
// with a result counter, and a visible fallback when the graph library is
// missing. Loaded before the other scripts, everything is wired on DOM ready
// so it can wrap the functions the table module declares.

const UI_VIEWS = {
    'hosts-view': { table: '#hosts-table', unit: 'hosts' },
    'ports-view': { table: '#ports-table', unit: 'ports' },
    'services-view': { table: '#services-table', unit: 'services' },
    'up-hosts-view': { table: '#up-hosts-table', unit: 'hosts' }
};

// Both filters are applied together, otherwise typing in the search box
// silently discards the TBD/Done selection and vice versa.
const uiFilterState = { term: '', status: 'all' };

function setTheme(theme) {
    document.documentElement.setAttribute('data-theme', theme);
    try {
        localStorage.setItem('unitasTheme', theme);
    } catch (e) {
        /* private mode: the theme simply does not persist */
    }
    updateThemeToggle();
}

function currentTheme() {
    const explicit = document.documentElement.getAttribute('data-theme');
    if (explicit) return explicit;
    return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches
        ? 'dark'
        : 'light';
}

function toggleTheme() {
    setTheme(currentTheme() === 'dark' ? 'light' : 'dark');
}

function updateThemeToggle() {
    const button = document.getElementById('theme-toggle');
    if (!button) return;
    const dark = currentTheme() === 'dark';
    button.textContent = dark ? 'Light mode' : 'Dark mode';
    button.setAttribute('aria-pressed', dark ? 'true' : 'false');
}

// Messages raised after the data is displayed used to be written into an
// element inside the (now hidden) landing screen, so nobody ever saw them.
function showToast(message, kind) {
    let toast = document.getElementById('toast');
    if (!toast) {
        toast = document.createElement('div');
        toast.id = 'toast';
        toast.className = 'copy-success';
        toast.setAttribute('role', 'status');
        toast.setAttribute('aria-live', 'polite');
        document.body.appendChild(toast);
    }

    toast.textContent = message;
    toast.classList.toggle('toast-error', kind === 'error');
    toast.classList.remove('hidden');

    clearTimeout(showToast.timer);
    showToast.timer = setTimeout(() => toast.classList.add('hidden'), 4000);
}

function activeViewId() {
    const active = document.querySelector('.view.active');
    return active ? active.id : null;
}

// The row builders write dataset.search; the fallback is only for rows built
// elsewhere. Reading row.textContent here instead used to cost three subtree
// traversals per row on every keystroke, and it swept in the labels of the
// status <select>, so searching "done" matched every single row.
function rowSearchText(row) {
    if (row.dataset.search !== undefined) {
        return row.dataset.search;
    }
    const text = row.textContent.replace(/\s+/g, ' ').trim().toLowerCase();
    row.dataset.search = text;
    return text;
}

function rowMatchesFilters(row, tableSelector) {
    if (uiFilterState.term && !rowSearchText(row).includes(uiFilterState.term)) {
        return false;
    }
    if (tableSelector === '#ports-table' && uiFilterState.status !== 'all') {
        // the status lives in the dataset; the cell holds a <select>
        const state = (row.dataset.state || '').toLowerCase();
        if (state !== uiFilterState.status) {
            return false;
        }
    }
    return true;
}

// Keeps a "no matches" row in sync so a filtered-to-empty table does not just
// look broken.
function updateNoMatchRow(table, visible, total) {
    const body = table.querySelector('tbody');
    if (!body) return;
    // held on the element: querySelector('.no-match-row') is a full scan of the
    // tbody and the row is appended last
    let row = table._noMatchRow;
    if (row && row.parentNode !== body) row = null;
    if (visible === 0 && total > 0) {
        if (!row) {
            row = document.createElement('tr');
            row.className = 'no-match-row';
            const cell = document.createElement('td');
            cell.className = 'empty-message';
            cell.colSpan = table.querySelectorAll('thead th').length || 1;
            cell.textContent = 'No rows match the current filters.';
            row.appendChild(cell);
            body.appendChild(row);
            table._noMatchRow = row;
        }
        row.style.display = '';
    } else if (row) {
        row.style.display = 'none';
    }
}

function applyUiFilters() {
    Object.keys(UI_VIEWS).forEach(viewId => {
        const table = document.querySelector(UI_VIEWS[viewId].table);
        if (!table) return;

        let visible = 0;
        let total = 0;
        const selector = UI_VIEWS[viewId].table;
        const body = table.tBodies[0];
        const rows = body ? body.rows : [];

        for (let i = 0; i < rows.length; i++) {
            const row = rows[i];
            // the placeholder rows are known, no need to probe every subtree
            if (row === table._noMatchRow || row.dataset.search === undefined) continue;
            total += 1;
            const show = rowMatchesFilters(row, selector);
            const display = show ? '' : 'none';
            if (row.style.display !== display) row.style.display = display;
            if (show) visible += 1;
        }

        table.dataset.visibleRows = String(visible);
        table.dataset.totalRows = String(total);
        updateNoMatchRow(table, visible, total);
    });

    updateResultCount();
}

// Re-evaluating one row after an edit, instead of sweeping every table
function refilterRow(table, row) {
    const selector = '#' + table.id;
    const wasVisible = row.style.display !== 'none';
    const show = rowMatchesFilters(row, selector);
    if (show === wasVisible) return;

    row.style.display = show ? '' : 'none';
    const visible = Number(table.dataset.visibleRows || 0) + (show ? 1 : -1);
    table.dataset.visibleRows = String(visible);
    updateNoMatchRow(table, visible, Number(table.dataset.totalRows || 0));
    updateResultCount();
}

function updateResultCount() {
    const label = document.getElementById('result-count');
    if (!label) return;

    const view = UI_VIEWS[activeViewId()];
    if (!view) {
        label.textContent = '';
        return;
    }

    const table = document.querySelector(view.table);
    if (!table || !table.dataset.totalRows) {
        label.textContent = '';
        return;
    }

    const visible = Number(table.dataset.visibleRows);
    const total = Number(table.dataset.totalRows);
    label.textContent = visible === total
        ? `${total} ${view.unit}`
        : `${visible} of ${total} ${view.unit}`;
}

// vis-network ships with the viewer, but the file can still be missing (a
// partial copy, a stripped package). Say so in the view instead of leaving an
// empty box and an error in the console.
function updateGraphAvailability() {
    const fallback = document.getElementById('graph-fallback');
    const container = document.getElementById('graph-container');
    if (!fallback || !container) return;

    // The overlays only make sense on top of a rendered graph
    const overlays = document.querySelectorAll('.graph-options, .graph-legend, .graph-minimap');
    const available = typeof vis !== 'undefined';

    overlays.forEach(el => el.classList.toggle('hidden', !available));

    if (available) {
        fallback.classList.add('hidden');
        container.classList.remove('hidden');
        return;
    }

    container.classList.add('hidden');
    fallback.classList.remove('hidden');
    if (fallback.childElementCount === 0) {
        const title = document.createElement('strong');
        title.textContent = 'Network graph unavailable';
        const text = document.createElement('p');
        text.textContent =
            'The graph library that ships with the viewer could not be loaded. ' +
            'Every other view still works; the file is expected at:';
        const cmd = document.createElement('code');
        cmd.textContent = 'static/js/vis-network.min.js';
        fallback.appendChild(title);
        fallback.appendChild(text);
        fallback.appendChild(cmd);
    }
}

// "Export current view" used to dump the whole data set, which is surprising
// when a search or status filter is active. Export what is on screen instead.
function exportVisibleRowsAsCSV() {
    const viewId = activeViewId();
    const view = UI_VIEWS[viewId];
    if (!view) {
        if (typeof showError === 'function') {
            showError('CSV export not available for this view');
        }
        return;
    }

    const table = document.querySelector(view.table);
    if (!table) return;

    // Reading the cells: the port rows carry everything on the row itself, the
    // other views are read from the DOM. Cloning each cell to strip the buttons
    // (the previous approach) meant a deep clone per cell.
    const cellText = cell => {
        const control = cell.querySelector('input');
        if (control) {
            const badge = cell.querySelector('.badge');
            return [badge ? badge.textContent.trim() : '', control.value]
                .filter(Boolean).join(' ').trim();
        }

        const items = cell.querySelectorAll('li');
        if (items.length) {
            return Array.from(items).map(li => li.textContent.trim()).join('; ');
        }

        return cell.textContent.replace(/\s+/g, ' ').trim();
    };

    const portRowCells = row => [
        row.dataset.ip,
        row.children[1].textContent.trim(),
        row.dataset.port,
        row.dataset.protocol,
        row.dataset.service,
        row.dataset.state,
        row.dataset.comment
    ];

    const headers = Array.from(table.querySelectorAll('thead th'))
        .map(th => cellText(th));
    const lines = [headers.map(quoteCsv).join(',')];

    const isPortsTable = viewId === 'ports-view';

    for (const row of table.tBodies[0].rows) {
        if (row.style.display === 'none') continue;
        if (row === table._noMatchRow || row.dataset.search === undefined) continue;
        const values = isPortsTable
            ? portRowCells(row)
            : Array.from(row.cells).map(cellText);
        lines.push(values.map(quoteCsv).join(','));
    }

    const csv = lines.join('\n');
    const filename = `unitas-${viewId.replace('-view', '')}.csv`;
    if (typeof downloadCSV === 'function') {
        downloadCSV(csv, filename);
    }
}

function quoteCsv(value) {
    return '"' + String(value).replace(/"/g, '""') + '"';
}

function setupThemeControls() {
    updateThemeToggle();

    const button = document.getElementById('theme-toggle');
    if (button) {
        button.addEventListener('click', toggleTheme);
    }

    document.addEventListener('keydown', event => {
        if (event.ctrlKey || event.metaKey || event.altKey) return;
        const tag = event.target.tagName;
        if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return;
        if (event.key === 't' || event.key === 'T') {
            event.preventDefault();
            toggleTheme();
        }
    });
}

// Search and the status buttons feed one combined pass; app.js calls these by
// name, they are the only definitions.
function filterTables(searchTerm) {
    uiFilterState.term = (searchTerm || '').toLowerCase();
    applyUiFilters();
}

function filterPortsTableByStatus(status) {
    uiFilterState.status = (status || 'all').toLowerCase();
    applyUiFilters();
}

function exportCurrentViewAsCSV() {
    exportVisibleRowsAsCSV();
}

function setupFilterOverrides() {
    // Recount whenever the tables are (re)built.
    if (typeof window.populateTables === 'function') {
        const populate = window.populateTables;
        window.populateTables = function () {
            populate.apply(this, arguments);
            applyUiFilters();
        };
    }

    // Re-count once the tables have been populated and whenever the view changes.
    document.querySelectorAll('.nav-item').forEach(item => {
        item.addEventListener('click', () => {
            document.querySelectorAll('.nav-item').forEach(other => {
                other.setAttribute('aria-selected', other === item ? 'true' : 'false');
            });
            // The view is switched by another handler, count after it ran
            setTimeout(() => {
                updateResultCount();
                if (item.getAttribute('data-view') === 'graph-view') {
                    updateGraphAvailability();
                }
            }, 0);
        });
    });
}

function setupShortcutsKeyboard() {
    const toggle = document.getElementById('shortcuts-toggle');
    if (!toggle) return;
    toggle.addEventListener('keydown', event => {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            toggle.click();
        }
    });
}

document.addEventListener('DOMContentLoaded', function () {
    setupThemeControls();
    setupFilterOverrides();
    setupShortcutsKeyboard();

    // Tables are filled by the other modules right after this handler, so the
    // first count is taken once the current task queue has drained.
    setTimeout(applyUiFilters, 0);
});
