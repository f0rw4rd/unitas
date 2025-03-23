// Filter and search functionality
let filteredItems = {
    hosts: new Set(),
    services: new Set(),
    nodes: new Set(),
    edges: new Set()
};

function applyFilters() {
    const serviceFilter = document.getElementById('service-filter').value;
    const portMin = parseInt(document.getElementById('port-min').value) || 1;
    const portMax = parseInt(document.getElementById('port-max').value) || 65535;
    const subnetFilter = document.getElementById('subnet-filter').value.trim();
    const showUncertain = document.getElementById('show-uncertain').checked;

    // Clear previous filter results
    filteredItems.hosts.clear();
    filteredItems.services.clear();
    filteredItems.nodes.clear();
    filteredItems.edges.clear();

    // Filter by service
    if (serviceFilter !== "all") {
        const serviceNodes = nodesDataset.get({
            filter: node => node.type === "service" && node.service === serviceFilter
        });

        serviceNodes.forEach(node => {
            filteredItems.services.add(node.id);

            // Add connected hosts to the filter list
            getConnectedHosts(node.id).forEach(hostId => {
                filteredItems.hosts.add(hostId);
            });
        });
    }

    // Filter by port range
    if (portMin > 1 || portMax < 65535) {
        scanData.hosts.forEach(host => {
            const portsInRange = host.ports.filter(port => {
                const portNumber = parseInt(port.port);
                return portNumber >= portMin && portNumber <= portMax;
            });

            if (portsInRange.length > 0) {
                const hostNodes = nodesDataset.get({
                    filter: node => node.type === "host" && node.ip === host.ip
                });

                if (hostNodes.length > 0) {
                    const hostNode = hostNodes[0];
                    filteredItems.hosts.add(hostNode.id);

                    // Add connected services to filter list
                    portsInRange.forEach(port => {
                        const serviceName = port.service.replace("?", "");
                        const serviceNodes = nodesDataset.get({
                            filter: node => node.type === "service" && node.service === serviceName
                        });

                        if (serviceNodes.length > 0) {
                            filteredItems.services.add(serviceNodes[0].id);
                        }
                    });
                }
            }
        });
    }

    // Filter by subnet
    if (subnetFilter) {
        const filteredNodes = nodesDataset.get({
            filter: node =>
                (node.type === "host" || node.type === "up-host") &&
                node.ip &&
                node.ip.startsWith(subnetFilter)
        });

        filteredNodes.forEach(node => {
            if (node.type === "host") {
                filteredItems.hosts.add(node.id);

                // Add connected services
                getConnectedServices(node.id).forEach(serviceId => {
                    filteredItems.services.add(serviceId);
                });
            } else {
                filteredItems.nodes.add(node.id);
            }
        });
    }

    // Filter uncertain services
    if (!showUncertain) {
        const uncertainServices = nodesDataset.get({
            filter: node => node.type === "service" && node.uncertain
        });

        uncertainServices.forEach(node => {
            filteredItems.nodes.add(node.id);
        });
    }

    // Apply filters by refreshing the graph
    try {
        refreshGraph();
    } catch (error) {
        console.error("Error applying filters:", error);
    }
}

function resetFilters() {
    document.getElementById('service-filter').value = "all";
    document.getElementById('port-min').value = "1";
    document.getElementById('port-max').value = "65535";
    document.getElementById('subnet-filter').value = "";
    document.getElementById('show-up-hosts').checked = true;
    document.getElementById('show-uncertain').checked = true;
    document.getElementById('highlight-tls').checked = true;

    filteredItems.hosts.clear();
    filteredItems.services.clear();
    filteredItems.nodes.clear();
    filteredItems.edges.clear();

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