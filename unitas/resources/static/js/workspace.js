// Live workspace: the page against a running `unitas <folder> -H`.
//
// The server owns the scan folder and the state.md beside it, so the triage
// belongs on the server rather than in this browser's localStorage. When the
// API answers, the edit accessors edits.js exports are replaced with ones that
// read the server's snapshot and POST changes back; when it does not (a single
// file report, a dropped JSON) nothing here runs and the localStorage path is
// untouched.

const WORKSPACE_POLL_MS = 2000;
const WORKSPACE_FLUSH_MS = 250;

const workspace = {
    active: false,
    version: 0,
    summary: null,
    // edits posted but not yet acknowledged, so a row can still show as pending
    pending: new Map(),
    queue: new Map(),
    hostQueue: new Map(),
    flushTimer: null,
    pollTimer: null,
    inFlight: false,
    offline: false
};

function workspaceEnabled() {
    return Boolean(window.UNITAS && window.UNITAS.live);
}

function workspaceReadOnly() {
    return Boolean(window.UNITAS && window.UNITAS.readOnly);
}

function workspaceFetch(path, options) {
    const settings = Object.assign({ cache: 'no-store' }, options);
    settings.headers = Object.assign(
        { 'X-Unitas-Token': (window.UNITAS && window.UNITAS.token) || '' },
        settings.headers
    );
    return fetch(path, settings).then(response => {
        if (!response.ok) {
            return response.json()
                .catch(() => ({}))
                .then(body => {
                    throw new Error(body.error || `${path} responded with ${response.status}`);
                });
        }
        return response.json();
    });
}

// ---------------------------------------------------------------- edit access

function workspaceEditId(ip, port) {
    return `${ip}|${port.protocol}|${port.port}`;
}

// The server has already merged the triage into the snapshot, so the port
// carries the real state; the only overlay is what has not been acknowledged.
function workspaceGetPortEdit(ip, port) {
    return workspace.pending.get(workspaceEditId(ip, port)) || null;
}

function workspaceEffectiveState(ip, port) {
    const pendingEdit = workspaceGetPortEdit(ip, port);
    if (pendingEdit && pendingEdit.state !== undefined) return pendingEdit.state;
    return port.state || 'TBD';
}

function workspaceEffectiveComment(ip, port) {
    const pendingEdit = workspaceGetPortEdit(ip, port);
    if (pendingEdit && pendingEdit.comment !== undefined) return pendingEdit.comment;
    return port.comment || '';
}

function workspaceSetPortEdit(ip, port, patch) {
    if (workspaceReadOnly()) {
        showToast('The workspace is read only, this edit was not saved', 'error');
        return;
    }

    const id = workspaceEditId(ip, port);
    workspace.pending.set(id, Object.assign({}, workspace.pending.get(id), patch));
    workspace.queue.set(
        id,
        Object.assign(
            { ip: ip, port: port.port, protocol: port.protocol },
            workspace.queue.get(id),
            patch
        )
    );
    workspaceScheduleFlush();
}

// Every port of a host in one request rather than one per row.
function workspaceSetHostState(ip, state) {
    if (workspaceReadOnly()) {
        showToast('The workspace is read only, this edit was not saved', 'error');
        return;
    }
    workspace.hostQueue.set(ip, { ip: ip, state: state });
    workspaceScheduleFlush();
}

function workspaceScheduleFlush() {
    workspaceUpdateIndicator();
    clearTimeout(workspace.flushTimer);
    workspace.flushTimer = setTimeout(workspaceFlush, WORKSPACE_FLUSH_MS);
}

function workspaceFlush() {
    clearTimeout(workspace.flushTimer);
    if (workspace.inFlight) {
        // one request at a time; whatever queued meanwhile goes in the next one
        workspace.flushTimer = setTimeout(workspaceFlush, WORKSPACE_FLUSH_MS);
        return;
    }
    if (workspace.queue.size === 0 && workspace.hostQueue.size === 0) return;

    const ports = Array.from(workspace.queue.values());
    const hosts = Array.from(workspace.hostQueue.values());
    const sent = Array.from(workspace.queue.keys());
    workspace.queue.clear();
    workspace.hostQueue.clear();
    workspace.inFlight = true;

    workspaceFetch('/api/edits', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ ports: ports, hosts: hosts })
    })
        .then(result => {
            workspace.inFlight = false;
            workspace.offline = false;
            // only clear what this request carried, a later edit to the same
            // port is still pending
            sent.forEach(id => {
                if (!workspace.queue.has(id)) workspace.pending.delete(id);
            });
            if (result.missing && result.missing.length) {
                showToast(`${result.missing.length} edit(s) no longer match the scan`, 'error');
            }
            workspaceUpdateIndicator();
            // pull the state the server wrote, so the page shows the file
            workspacePoll();
        })
        .catch(error => {
            workspace.inFlight = false;
            workspace.offline = true;
            // put them back, the next flush retries
            ports.forEach(edit => {
                const id = `${edit.ip}|${edit.protocol}|${edit.port}`;
                if (!workspace.queue.has(id)) workspace.queue.set(id, edit);
            });
            hosts.forEach(edit => {
                if (!workspace.hostQueue.has(edit.ip)) workspace.hostQueue.set(edit.ip, edit);
            });
            showToast(`Could not save the edit: ${error.message}`, 'error');
            workspaceUpdateIndicator();
        });
}

function workspaceEditCount() {
    return workspace.pending.size;
}

function workspaceUpdateIndicator() {
    const label = document.getElementById('edit-count');
    if (!label) return;

    const unsaved = workspace.pending.size;
    if (workspace.offline) {
        label.textContent = 'not saved: the server is unreachable';
        label.dataset.tone = 'error';
    } else if (unsaved) {
        label.textContent = `saving ${unsaved}...`;
        label.dataset.tone = 'busy';
    } else if (workspaceReadOnly()) {
        label.textContent = 'read only';
        label.dataset.tone = 'error';
    } else if (workspace.summary) {
        const done = workspace.summary.done || 0;
        const ports = workspace.summary.ports || 0;
        const percent = ports ? Math.round((done / ports) * 100) : 0;
        label.textContent = `${done}/${ports} done (${percent}%) - state.md is live`;
        label.dataset.tone = '';
    }

    const reset = document.getElementById('reset-edits-btn');
    if (reset) reset.disabled = true;
}

// ------------------------------------------------------------------- syncing

function workspaceApply(payload) {
    workspace.version = payload.version;
    workspace.summary = payload.summary || workspace.summary;

    if (!payload.data) {
        workspaceUpdateIndicator();
        return;
    }

    const previous = workspaceCounts();
    window.scanData = payload.data;

    if (document.getElementById('data-view').classList.contains('hidden')) {
        validateAndDisplayData(payload.data);
    } else {
        workspaceRerender();
        workspaceAnnounce(previous, workspaceCounts());
    }
    workspaceUpdateIndicator();
}

function workspaceCounts() {
    const data = window.scanData;
    if (!data || !data.hosts) return { hosts: 0, ports: 0 };
    return {
        hosts: data.hosts.length,
        ports: data.hosts.reduce((total, host) => total + host.ports.length, 0)
    };
}

function workspaceAnnounce(before, after) {
    const hosts = after.hosts - before.hosts;
    const ports = after.ports - before.ports;
    if (!hosts && !ports) return;

    const parts = [];
    if (hosts) parts.push(`${hosts > 0 ? '+' : ''}${hosts} host${Math.abs(hosts) === 1 ? '' : 's'}`);
    if (ports) parts.push(`${ports > 0 ? '+' : ''}${ports} port${Math.abs(ports) === 1 ? '' : 's'}`);
    showToast(`Scan updated: ${parts.join(', ')}`);
}

// A re-render throws away the row the tester is typing in, so it waits until
// they are done rather than eating a comment halfway through.
function workspaceRerender() {
    const focused = document.activeElement;
    if (focused && focused.dataset && focused.dataset.commentInput !== undefined) {
        workspace.deferredRender = true;
        focused.addEventListener('blur', () => {
            if (workspace.deferredRender) {
                workspace.deferredRender = false;
                workspaceRerender();
            }
        }, { once: true });
        return;
    }

    const service = document.getElementById('service-filter');
    const selectedService = service ? service.value : 'all';

    updateStats();
    populateTables();
    populateServiceFilter();
    if (service && Array.from(service.options).some(o => o.value === selectedService)) {
        service.value = selectedService;
    }
    applyUiFilters();

    // the graph is expensive and only correct once rebuilt; do it when it is
    // on screen and leave it to the tab switch otherwise
    if (document.getElementById('graph-view').classList.contains('active')) {
        renderGraph();
    } else if (typeof network !== 'undefined' && network) {
        network.destroy();
        network = null;
    }
}

function workspacePoll() {
    return workspaceFetch(`/api/state?version=${workspace.version}`)
        .then(payload => {
            workspace.offline = false;
            workspaceApply(payload);
        })
        .catch(error => {
            if (!workspace.offline) {
                workspace.offline = true;
                workspaceUpdateIndicator();
                console.warn('Workspace poll failed:', error.message);
            }
        });
}

function workspaceRescan() {
    return workspaceFetch('/api/rescan', { method: 'POST' })
        .then(result => {
            showToast(result.changed ? 'Folder re-read' : 'Nothing new in the folder');
            return workspacePoll();
        })
        .catch(error => showToast(`Rescan failed: ${error.message}`, 'error'));
}

function workspaceStart() {
    workspace.active = true;

    // take over the triage accessors; every caller goes through window
    window.getPortEdit = workspaceGetPortEdit;
    window.effectiveState = workspaceEffectiveState;
    window.effectiveComment = workspaceEffectiveComment;
    window.setPortEdit = workspaceSetPortEdit;
    window.editCount = workspaceEditCount;
    window.loadEdits = function () { return {}; };
    window.writeEdits = function () { };
    window.clearEdits = function () { };
    window.updateEditIndicator = workspaceUpdateIndicator;

    // the live server owns the folder; loading a different file would leave the
    // page editing a snapshot while still POSTing to this workspace
    const reload = document.getElementById('reload-btn');
    if (reload) reload.classList.add('hidden');
    const reset = document.getElementById('reset-edits-btn');
    if (reset) reset.classList.add('hidden');
    const rescan = document.getElementById('rescan-btn');
    if (rescan) {
        rescan.classList.remove('hidden');
        rescan.addEventListener('click', workspaceRescan);
    }
    const exportState = document.getElementById('export-state-btn');
    if (exportState && window.UNITAS.stateFile) {
        exportState.title = `The live state is at ${window.UNITAS.stateFile}`;
    }

    showLoading();
    workspacePoll()
        .then(() => hideLoading())
        .catch(() => hideLoading());

    workspace.pollTimer = setInterval(() => {
        if (document.visibilityState === 'visible') workspacePoll();
    }, WORKSPACE_POLL_MS);

    // coming back to the tab should not wait out the interval
    window.addEventListener('focus', () => workspacePoll());
    window.addEventListener('beforeunload', () => {
        if (workspace.queue.size || workspace.hostQueue.size) workspaceFlush();
    });
}

// The bootstrap is injected into the head, so window.UNITAS is already set;
// the check is repeated at DOMContentLoaded so load order cannot decide it.
document.addEventListener('DOMContentLoaded', function () {
    if (workspaceEnabled()) workspaceStart();
});
