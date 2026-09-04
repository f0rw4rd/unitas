// Graph sidebar filters.
//
// The filters are predicates evaluated by createGraphData() while it builds the
// nodes and edges. An earlier version collected matching ids into a set and then
// rebuilt the graph from the unfiltered data, so none of the controls except
// "show hosts without open ports" had any effect.

function getGraphFilters() {
    const value = (id, fallback) => {
        const element = document.getElementById(id);
        return element ? element.value : fallback;
    };
    const checked = (id, fallback) => {
        const element = document.getElementById(id);
        return element ? element.checked : fallback;
    };

    return {
        service: value('service-filter', 'all'),
        portMin: parseInt(value('port-min', '1'), 10) || 1,
        portMax: parseInt(value('port-max', '65535'), 10) || 65535,
        subnet: value('subnet-filter', '').trim(),
        showUncertain: checked('show-uncertain', true),
        showUpHosts: checked('show-up-hosts', true)
    };
}

function hostMatchesFilters(host, filters) {
    if (filters.subnet && !host.ip.startsWith(filters.subnet)) {
        return false;
    }
    return true;
}

function portMatchesFilters(port, filters) {
    const portNumber = parseInt(port.port, 10);
    if (portNumber < filters.portMin || portNumber > filters.portMax) {
        return false;
    }

    if (filters.service !== 'all' && port.service.replace('?', '') !== filters.service) {
        return false;
    }

    if (!filters.showUncertain && (port.uncertain || port.service.includes('?'))) {
        return false;
    }

    return true;
}

// Tells the user what the filters actually did, so an empty graph is
// distinguishable from a broken one.
function updateFilterSummary(counts) {
    const summary = document.getElementById('filter-summary');
    if (!summary) return;

    if (counts.hosts === counts.totalHosts && counts.ports === counts.totalPorts) {
        summary.textContent = `${counts.totalHosts} hosts, ${counts.totalPorts} ports`;
        return;
    }

    summary.textContent =
        `${counts.hosts} of ${counts.totalHosts} hosts, ` +
        `${counts.ports} of ${counts.totalPorts} ports`;
}

function applyFilters() {
    refreshGraph();
}

function resetFilters() {
    document.getElementById('service-filter').value = "all";
    document.getElementById('port-min').value = "1";
    document.getElementById('port-max').value = "65535";
    document.getElementById('subnet-filter').value = "";
    document.getElementById('show-up-hosts').checked = true;
    document.getElementById('show-uncertain').checked = true;
    document.getElementById('highlight-tls').checked = true;

    refreshGraph();
}

function refreshGraph() {
    if (network) {
        network.destroy();
        network = null;
    }
    if (minimapNetwork) {
        minimapNetwork.destroy();
        minimapNetwork = null;
    }

    // Clear datasets to prevent issues with stale data
    nodesDataset = null;
    edgesDataset = null;

    renderGraph();

    if (nodesDataset && document.getElementById('highlight-tls').checked) {
        highlightTlsServices();
    }
}

function highlightTlsServices() {
    // Check if nodesDataset exists before trying to use it
    if (!nodesDataset) {
        console.log("Cannot highlight TLS services: nodesDataset is not initialized");
        return;
    }

    const highlight = document.getElementById('highlight-tls').checked;

    try {
        // Get all service nodes that have TLS
        const tlsNodes = nodesDataset.get({
            filter: node => node.type === "service" && node.tls
        });

        // Update each node with appropriate color
        if (tlsNodes && tlsNodes.length > 0) {
            tlsNodes.forEach(node => {
                nodesDataset.update({
                    id: node.id,
                    color: highlight ? {
                        border: "#e74c3c",
                        background: "#e74c3c",
                        highlight: {
                            border: "#c0392b",
                            background: "#e74c3c"
                        }
                    } : null
                });
            });
        }
    } catch (error) {
        console.error("Error highlighting TLS services:", error);
    }
}
