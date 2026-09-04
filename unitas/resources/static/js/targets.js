// Target lists for the next tool in the chain (EyeWitness, httpx, nmap).
//
// The rules mirror generate_service_urls() and generate_nmap_scan_command() in
// the Python package so `unitas <folder> -w` and "Copy Visible" agree. Keeping
// them here rather than precomputing URLs in the JSON means the viewer also
// works with files written by an older unitas. tests/test_unitas.py asserts the
// two port tables below stay in sync with unitas/utils.py.

const WEB_PORT_HINTS = [
    "80", "81", "88", "591", "3000", "5000", "7001", "8000", "8008", "8080",
    "8081", "8082", "8088", "8888", "9080", "10000"
];
const TLS_PORT_HINTS = [
    "443", "832", "981", "1311", "4443", "7002", "8443", "8834", "9443", "10443"
];

function isWebService(port) {
    const service = (port.service || '').toLowerCase();
    if (service.includes('http') || service.includes('www')) {
        return true;
    }
    if (service.includes('?') || service.includes('unknown')) {
        return WEB_PORT_HINTS.includes(port.port) || TLS_PORT_HINTS.includes(port.port);
    }
    return false;
}

function usesTls(port) {
    const service = (port.service || '').toLowerCase();
    const comment = (port.comment || '').toLowerCase();
    if (service.includes('https') || service.includes('ssl') || service.includes('tls')) {
        return true;
    }
    if (comment.includes('tls') || comment.includes('ssl')) {
        return true;
    }
    return TLS_PORT_HINTS.includes(port.port);
}

// IPv6 literals need brackets in a URL authority
function formatHost(ip) {
    return ip.includes(':') ? `[${ip}]` : ip;
}

function serviceUrl(ip, port, mode) {
    if (mode === 'web') {
        if (port.protocol !== 'tcp' || !isWebService(port)) return null;
        return `${usesTls(port) ? 'https' : 'http'}://${formatHost(ip)}:${port.port}`;
    }

    const scheme = (port.service || '').toLowerCase().replace(/\?/g, '').trim();
    if (!scheme || scheme.includes('unknown')) return null;
    return `${scheme.replace(/\//g, '-')}://${formatHost(ip)}:${port.port}`;
}

// The ports currently visible in the ports view, as {ip, port, protocol,
// service, comment} records taken from the scan data.
function visiblePorts() {
    const rows = document.querySelectorAll('#ports-table tbody tr');
    const wanted = new Set();

    rows.forEach(row => {
        if (row.style.display === 'none' || !row.dataset.ip) return;
        wanted.add(`${row.dataset.ip}|${row.dataset.protocol}|${row.dataset.port}`);
    });

    const ports = [];
    (window.scanData ? window.scanData.hosts : []).forEach(host => {
        host.ports.forEach(port => {
            if (wanted.has(`${host.ip}|${port.protocol}|${port.port}`)) {
                ports.push(Object.assign({ ip: host.ip }, port));
            }
        });
    });
    return ports;
}

function buildTargetList(kind) {
    const ports = visiblePorts();

    if (ports.length === 0) {
        return '';
    }

    if (kind === 'nmap') {
        return buildRescanCommand(ports);
    }

    const lines = [];
    const seen = new Set();

    ports.forEach(port => {
        let value = null;
        if (kind === 'urls-web') {
            value = serviceUrl(port.ip, port, 'web');
        } else if (kind === 'urls-all') {
            value = serviceUrl(port.ip, port, 'all');
        } else if (kind === 'ip-port') {
            value = `${port.ip}:${port.port}`;
        } else if (kind === 'ips') {
            value = port.ip;
        }

        if (value && !seen.has(value)) {
            seen.add(value);
            lines.push(value);
        }
    });

    return lines.join('\n');
}

// Mirrors generate_nmap_scan_command(): re-scan whatever has no confirmed
// service yet.
function buildRescanCommand(ports) {
    const tcp = new Set();
    const udp = new Set();
    const targets = new Set();
    const scanTypes = new Set();

    ports.forEach(port => {
        if (!(port.service || '').includes('?') && !port.uncertain) return;
        if (port.protocol === 'tcp') {
            tcp.add(port.port);
            scanTypes.add('S');
        } else if (port.protocol === 'udp') {
            udp.add(port.port);
            scanTypes.add('U');
        }
        targets.add(port.ip);
    });

    if (tcp.size === 0 && udp.size === 0) {
        return '';
    }

    let portSpec = '-p';
    if (tcp.size) portSpec += 'T:' + Array.from(tcp).join(',');
    if (udp.size) portSpec += (tcp.size ? ',' : '') + 'U:' + Array.from(udp).join(',');

    return `sudo nmap -n -r --reason -Pn -s${Array.from(scanTypes).join('')} -sV -v ` +
        `${portSpec} ${Array.from(targets).join(' ')}`;
}

function copyTargetList(kind) {
    const content = buildTargetList(kind);

    if (!content) {
        showError(kind === 'nmap'
            ? 'Nothing to re-scan: every visible port has an identified service'
            : 'No visible ports match that target format');
        return;
    }

    const count = kind === 'nmap' ? 1 : content.split('\n').length;
    copyToClipboard(content, `Copied ${count} ${count === 1 ? 'entry' : 'entries'}`);
}

function setupCopyMenu() {
    const menu = document.getElementById('copy-menu');
    const button = document.getElementById('copy-menu-btn');
    const panel = document.getElementById('copy-menu-panel');
    if (!menu || !button || !panel) return;

    const close = () => {
        panel.classList.add('hidden');
        button.setAttribute('aria-expanded', 'false');
    };

    button.addEventListener('click', event => {
        event.stopPropagation();
        const open = panel.classList.toggle('hidden') === false;
        button.setAttribute('aria-expanded', open ? 'true' : 'false');
    });

    panel.querySelectorAll('[data-copy]').forEach(item => {
        item.addEventListener('click', () => {
            close();
            copyTargetList(item.getAttribute('data-copy'));
        });
    });

    document.addEventListener('click', event => {
        if (!menu.contains(event.target)) close();
    });
    document.addEventListener('keydown', event => {
        if (event.key === 'Escape') close();
    });
}
