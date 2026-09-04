// Triage edits.
//
// The scan JSON is a snapshot, but the state a tester keeps (which ports are
// done, what was found on them) belongs to the engagement. Those edits are held
// in localStorage next to the scan they belong to and can be written back out
// as a state.md that `unitas -u` merges into the next run.

const EDITS_PREFIX = 'unitas:edits:';

let portEdits = {};
let portEditsKey = null;

function scanEditsKey() {
    const meta = (window.scanData && window.scanData.metadata) || {};
    const hosts = (window.scanData && window.scanData.hosts) || [];
    const id = `${meta.generated || 'unknown'}|${hosts.length}`;
    return EDITS_PREFIX + id;
}

function portEditId(ip, port) {
    return `${ip}|${port.protocol}|${port.port}`;
}

function loadEdits() {
    portEditsKey = scanEditsKey();
    try {
        portEdits = JSON.parse(localStorage.getItem(portEditsKey)) || {};
    } catch (error) {
        portEdits = {};
    }
    updateEditIndicator();
    return portEdits;
}

function persistEdits() {
    if (!portEditsKey) portEditsKey = scanEditsKey();
    try {
        if (Object.keys(portEdits).length === 0) {
            localStorage.removeItem(portEditsKey);
        } else {
            localStorage.setItem(portEditsKey, JSON.stringify(portEdits));
        }
    } catch (error) {
        showError('Could not store the edit: browser storage is unavailable');
    }
    updateEditIndicator();
}

function getPortEdit(ip, port) {
    return portEdits[portEditId(ip, port)] || null;
}

// The scan value unless the tester overrode it
function effectiveState(ip, port) {
    const edit = getPortEdit(ip, port);
    if (edit && edit.state !== undefined) return edit.state;
    return port.state || 'TBD';
}

function effectiveComment(ip, port) {
    const edit = getPortEdit(ip, port);
    if (edit && edit.comment !== undefined) return edit.comment;
    return port.comment || '';
}

function setPortEdit(ip, port, patch) {
    const id = portEditId(ip, port);
    const merged = Object.assign({}, portEdits[id], patch);

    // drop the entry again once it matches the scan
    const scanState = port.state || 'TBD';
    const scanComment = port.comment || '';
    if ((merged.state === undefined || merged.state === scanState) &&
        (merged.comment === undefined || merged.comment === scanComment)) {
        delete portEdits[id];
    } else {
        portEdits[id] = merged;
    }

    persistEdits();
}

function editCount() {
    return Object.keys(portEdits).length;
}

function clearEdits() {
    portEdits = {};
    persistEdits();
    populateTables();
}

function updateEditIndicator() {
    const label = document.getElementById('edit-count');
    if (!label) return;

    const count = editCount();
    label.textContent = count === 0 ? '' : `${count} edited`;
    const reset = document.getElementById('reset-edits-btn');
    if (reset) reset.disabled = count === 0;
}

// Writes the markdown state file that MarkdownConvert.parse() reads, so the
// triage done here survives into the next `unitas -u` run.
function exportStateMarkdown() {
    if (!window.scanData) return;

    const withOrigin = Boolean(
        window.scanData.metadata && window.scanData.metadata.includesOrigin
    );

    const header = withOrigin
        ? '|IP|Hostname|Port|Status|Comment|Source|\n|--|--|--|--|---|---|\n'
        : '|IP|Hostname|Port|Status|Comment|\n|--|--|--|--|---|\n';

    let markdown = header;

    window.scanData.hosts.slice().sort((a, b) => compareIps(a.ip, b.ip)).forEach(host => {
        host.ports.slice()
            .sort((a, b) => parseInt(a.port, 10) - parseInt(b.port, 10))
            .forEach(port => {
                const cells = [
                    host.ip,
                    escapeMarkdownCell(host.hostname),
                    `${port.port}/${port.protocol}(${port.service})`,
                    escapeMarkdownCell(effectiveState(host.ip, port)),
                    escapeMarkdownCell(effectiveComment(host.ip, port))
                ];

                if (withOrigin) {
                    cells.push(escapeMarkdownCell(formatSources(port.sources)));
                }

                markdown += `|${cells.join('|')}|\n`;
            });
    });

    downloadTextFile(markdown, 'state.md', 'text/markdown');
}

// Same shape the markdown converter writes: "type:file", comma separated
function formatSources(sources) {
    if (!Array.isArray(sources)) return '';
    return sources
        .map(source => [source.type, source.file].filter(Boolean).join(':'))
        .filter(Boolean)
        .join(',');
}

function downloadTextFile(content, filename, mimeType) {
    const blob = new Blob([content], { type: `${mimeType || 'text/plain'};charset=utf-8` });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = filename;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
}
