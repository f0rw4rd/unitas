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

function isEmptyMessageRow(row) {
    return row.querySelector('.empty-message') !== null;
}

// The searchable text of a row: its cells plus the values of the editable
// controls, which contribute nothing to textContent.
function rowSearchText(row) {
    const values = Array.from(row.querySelectorAll('input, select'))
        .map(control => control.value)
        .join(' ');
    return `${row.textContent} ${values}`.toLowerCase();
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
    let row = body.querySelector('.no-match-row');
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
        table.querySelectorAll('tbody tr').forEach(row => {
            if (row.classList.contains('no-match-row')) return;
            if (isEmptyMessageRow(row)) return;
            total += 1;
            const show = rowMatchesFilters(row, UI_VIEWS[viewId].table);
            row.style.display = show ? '' : 'none';
            if (show) visible += 1;
        });

        table.dataset.visibleRows = String(visible);
        table.dataset.totalRows = String(total);
        updateNoMatchRow(table, visible, total);
    });

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

    const cellText = cell => {
        // form controls carry their value in .value, not in the text
        const control = cell.querySelector('input, select');
        if (control) {
            const badge = cell.querySelector('.badge');
            return [badge ? badge.textContent.trim() : '', control.value]
                .filter(Boolean)
                .join(' ')
                .trim();
        }

        const copy = cell.cloneNode(true);
        copy.querySelectorAll('button').forEach(button => button.remove());
        const items = copy.querySelectorAll('li');
        const text = items.length
            ? Array.from(items).map(li => li.textContent.trim()).join('; ')
            : copy.textContent;
        return text.replace(/\s+/g, ' ').trim();
    };

    const headers = Array.from(table.querySelectorAll('thead th'))
        .map(th => cellText(th));
    const lines = [headers.map(quoteCsv).join(',')];

    table.querySelectorAll('tbody tr').forEach(row => {
        if (row.style.display === 'none') return;
        if (row.classList.contains('no-match-row') || isEmptyMessageRow(row)) return;
        const cells = Array.from(row.querySelectorAll('td')).map(cell => quoteCsv(cellText(cell)));
        lines.push(cells.join(','));
    });

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
