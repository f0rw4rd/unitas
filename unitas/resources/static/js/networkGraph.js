// Network graph visualization
let network = null;
let nodesDataset = null;
let edgesDataset = null;
let minimapNetwork = null;
let physicsEnabled = true;
let selectedNode = null;
let pinnedNodes = new Set();
let savedViews = {};

// Graph generation functions
function renderGraph() {
    if (!scanData) {
        console.error("Cannot render graph: scanData is not available");
        return;
    }

    // Check for required dependencies
    if (typeof vis === 'undefined') {
        console.error("Cannot render graph: vis.js is not loaded");
        return;
    }

    const container = document.getElementById('graph-container');
    if (!container) {
        console.error("Cannot render graph: graph container element not found");
        return;
    }

    try {
        // Clear previous graph
        if (network) {
            network.destroy();
            network = null;
        }

        highlightedNodes = [];
        highlightedEdges = [];

        // Process subnets for the network graph
        processSubnets();

        const { nodes, edges } = createGraphData();

        if (!nodes || !edges) {
            console.error("Failed to create graph data");
            return;
        }

        // Initialize datasets with error handling
        try {
            nodesDataset = new vis.DataSet(nodes);
            edgesDataset = new vis.DataSet(edges);
        } catch (error) {
            console.error("Error creating datasets:", error);
            return;
        }

        // Create graph data
        const data = {
            nodes: nodesDataset,
            edges: edgesDataset
        };

        // Configure graph options
        const options = createGraphOptions();

        // Create network with error handling
        try {
            network = new vis.Network(container, data, options);
            console.log("Network graph created successfully");
        } catch (error) {
            console.error("Error creating network graph:", error);
            return;
        }

        setupNetworkEvents();

        if (document.querySelector('input[name="layout"]:checked').value === "circular") {
            placeNodesInCircle();
        }

        try {
            initializeMinimap(nodes, edges);
        } catch (error) {
            console.error("Error initializing minimap (non-critical):", error);
            // Continue even if minimap fails
        }

    } catch (error) {
        console.error("Error in renderGraph:", error);
    }
}

function createGraphData() {
    const nodes = [];
    const edges = [];
    let nextId = 1;
    const nodeIdMap = {};
    const servicesMap = new Map();

    // The sidebar filters are applied while the graph is built; anything else
    // would be thrown away by the rebuild.
    const filters = getGraphFilters();
    const counts = { hosts: 0, totalHosts: 0, ports: 0, totalPorts: 0 };
    const serviceCounts = countServices(window.scanData.hosts, filters);

    // Process hosts
    window.scanData.hosts.forEach((host) => {
        counts.totalHosts += 1;
        counts.totalPorts += host.ports.length;

        if (!hostMatchesFilters(host, filters)) return;

        const ports = host.ports.filter(port => portMatchesFilters(port, filters));
        if (ports.length === 0) return;

        const hostId = nextId++;
        nodeIdMap[host.ip] = hostId;
        counts.hosts += 1;
        counts.ports += ports.length;

        // Calculate value based on number of ports
        const portCount = ports.length;

        nodes.push({
            id: hostId,
            label: host.hostname || host.ip,
            title: formatNodeTooltip(host),
            group: "host",
            subnetGroup: getSubnet(host.ip),
            type: "host",
            ip: host.ip,
            hostname: host.hostname,
            value: Math.max(10, Math.min(30, 10 + 2 * portCount)),
            ports: portCount,
            original: host
        });

        // Process services on this host
        const hostServices = {};

        ports.forEach((port) => {
            const serviceName = port.service.replace("?", "");

            if (!hostServices[serviceName]) {
                hostServices[serviceName] = [];
            }
            hostServices[serviceName].push(port);
        });

        // Create edges between host and services
        Object.entries(hostServices).forEach(([serviceName, ports]) => {
            let serviceId;

            if (servicesMap.has(serviceName)) {
                serviceId = servicesMap.get(serviceName);
            } else {
                serviceId = nextId++;
                servicesMap.set(serviceName, serviceId);

                // Count total instances of this service
                const serviceInstances = countServiceInstances(serviceCounts, serviceName);

                nodes.push({
                    id: serviceId,
                    label: serviceName,
                    title: `<strong>${serviceName}</strong><br>Instances: ${serviceInstances}`,
                    group: "service",
                    type: "service",
                    value: Math.max(8, Math.min(25, 8 + serviceInstances)),
                    service: serviceName,
                    uncertain: ports.some(p => p.service.includes("?") || p.uncertain),
                    tls: ports.some(p => p.comment && p.comment.includes("TLS") || p.tls)
                });
            }

            edges.push({
                from: hostId,
                to: serviceId,
                title: formatEdgeTooltip(ports),
                width: Math.max(1, Math.min(5, Math.sqrt(2 * ports.length))),
                arrows: { to: { enabled: false } },
                color: { color: "#999", highlight: "#3498db" },
                smooth: { type: "continuous" },
                ports: ports
            });
        });
    });

    // Add hosts that are up but have no open ports
    if (window.scanData.hostsUp && filters.showUpHosts) {
        window.scanData.hostsUp.forEach((host) => {
            if (filters.subnet && !host.ip.startsWith(filters.subnet)) return;
            // an up host has no service or port to match against
            if (filters.service !== "all" || filters.portMin > 1 || filters.portMax < 65535) {
                return;
            }
            nodes.push({
                id: nextId++,
                label: host.ip,
                title: `<strong>${host.ip}</strong><br>Up: ${host.reason}`,
                group: "up-only",
                type: "up-host",
                ip: host.ip,
                reason: host.reason,
                value: 8,
                subnetGroup: getSubnet(host.ip)
            });
        });
    }

    updateFilterSummary(counts);
    return { nodes, edges };
}

function createGraphOptions() {
    const nodeSize = parseInt(document.getElementById("node-size").value);

    return {
        nodes: {
            shape: "dot",
            scaling: {
                min: Math.max(5, nodeSize - 10),
                max: nodeSize + 10,
                label: {
                    enabled: true,
                    min: 14,
                    max: 24
                }
            },
            font: { size: 14 },
            borderWidth: 2,
            shadow: true
        },
        edges: {
            width: 2,
            shadow: true,
            smooth: { type: "continuous" }
        },
        groups: {
            host: {
                color: { border: "#2980b9", background: "#3498db", highlight: { border: "#2980b9", background: "#5DADF5" } },
                shape: "dot"
            },
            service: {
                color: { border: "#27ae60", background: "#2ecc71", highlight: { border: "#27ae60", background: "#58D88D" } },
                shape: "hexagon"
            },
            "up-only": {
                color: { border: "#d35400", background: "#e67e22", highlight: { border: "#d35400", background: "#EB9950" } },
                shape: "diamond"
            },
            pinned: {
                color: { border: "#8e44ad", background: "#9b59b6", highlight: { border: "#8e44ad", background: "#ac6fc6" } },
                fixed: true
            }
        },
        physics: {
            enabled: physicsEnabled,
            stabilization: true,
            barnesHut: {
                gravitationalConstant: -10000,
                springConstant: 0.002,
                springLength: 150
            }
        },
        interaction: {
            hover: true,
            tooltipDelay: 200,
            hideEdgesOnDrag: true,
            multiselect: true,
            navigationButtons: true
        },
        layout: getSelectedLayout()
    };
}

function getSelectedLayout() {
    switch (document.querySelector('input[name="layout"]:checked').value) {
        case "hierarchical":
            return {
                hierarchical: {
                    direction: "UD",
                    sortMethod: "directed",
                    nodeSpacing: 150,
                    levelSeparation: 150
                }
            };
        case "circular":
            // positions are assigned in placeNodesInCircle() once the nodes
            // exist, the layout engine itself has no circular mode
            return {
                improvedLayout: false,
                randomSeed: 42
            };
        default:
            return {
                improvedLayout: true
            };
    }
}

// vis has no circular layout, so place the nodes on two rings by hand: hosts
// outside, the shared service nodes inside, with physics off so they stay put.
function placeNodesInCircle() {
    if (!network || !nodesDataset) return;

    const all = nodesDataset.get();
    const hosts = all.filter(node => node.type !== "service");
    const services = all.filter(node => node.type === "service");
    const radius = Math.max(300, all.length * 12);

    const place = (list, ringRadius) => {
        list.forEach((node, index) => {
            const angle = (2 * Math.PI * index) / Math.max(1, list.length);
            network.moveNode(
                node.id,
                Math.cos(angle) * ringRadius,
                Math.sin(angle) * ringRadius
            );
        });
    };

    network.setOptions({ physics: { enabled: false } });
    physicsEnabled = false;
    place(hosts, radius);
    place(services, radius / 2.2);
    network.fit();
}

function setupNetworkEvents() {
    if (!network) return;

    network.on("click", function (params) {
        if (params.nodes.length === 0) {
            document.getElementById('node-details').style.display = "none";
            selectedNode = null;
            return;
        }

        selectedNode = nodesDataset.get(params.nodes[0]);
        showNodeDetails(selectedNode);
        highlightConnections(params.nodes[0]);
    });

    network.on("doubleClick", function (params) {
        if (params.nodes.length === 1) {
            network.focus(params.nodes[0], {
                scale: 1.2,
                animation: true
            });
        }
    });

    network.on("hoverNode", function (params) {
        // Make sure we have valid event coordinates
        if (params.event && params.event.center) {
            showTooltip(params.node, params.event.center);
        }
    });

    network.on("blurNode", function () {
        hideTooltip();
    });

    network.on("hoverEdge", function (params) {
        // Make sure we have valid event coordinates
        if (params.event && params.event.center) {
            const edgeData = edgesDataset.get(params.edge);
            showTooltip(params.edge, params.event.center, true, edgeData);
        }
    });

    network.on("blurEdge", function () {
        hideTooltip();
    });

    network.on("stabilizationProgress", function (params) {
        const progress = Math.round(params.iterations / params.total * 100);
        console.log(`Stabilizing: ${progress}%`);
    });

    network.on("stabilizationIterationsDone", function () {
        console.log("Stabilization complete");
        if (minimapNetwork) {
            updateMinimap();
        }
    });
}


// Tooltip and node details functions
function showNodeDetails(node) {
    const nodeDetails = document.getElementById('node-details');
    nodeDetails.style.display = "block";
    let content = "";

    switch (node.type) {
        case "host":
            content = `
                <dl>
                    <dt>IP Address:</dt>
                    <dd>${node.ip}</dd>
                    ${node.hostname ? `<dt>Hostname:</dt><dd>${node.hostname}</dd>` : ""}
                    <dt>Open Ports:</dt>
                    <dd>${node.ports} port(s)</dd>
                </dl>
                <h4>Ports:</h4>
                <ul>
            `;

            node.original.ports.forEach(port => {
                content += `<li>${port.port}/${port.protocol} (${port.service}) - ${port.state || 'TBD'}</li>`;
            });

            content += "</ul>";
            break;

        case "service":
            content = `
                <dl>
                    <dt>Service:</dt>
                    <dd>${node.service}</dd>
                    <dt>Status:</dt>
                    <dd>${node.uncertain ? "Uncertain" : "Confirmed"}</dd>
                    ${node.tls ? "<dt>Security:</dt><dd>TLS Enabled</dd>" : ""}
                </dl>
                <h4>Connected Hosts:</h4>
                <ul>
            `;

            getConnectedHosts(node.id).forEach(hostId => {
                const hostNode = nodesDataset.get(hostId);
                content += `<li>${hostNode.ip}${hostNode.hostname ? ` (${hostNode.hostname})` : ""}</li>`;
            });

            content += "</ul>";
            break;

        case "up-host":
            content = `
                <dl>
                    <dt>IP Address:</dt>
                    <dd>${node.ip}</dd>
                    <dt>Status:</dt>
                    <dd>Up (no open ports)</dd>
                    <dt>Reason:</dt>
                    <dd>${node.reason}</dd>
                </dl>
            `;
            break;
    }

    document.getElementById("pin-node").textContent = pinnedNodes.has(node.id) ? "Unpin Node" : "Pin Node";
    document.getElementById('node-details-content').innerHTML = content;
}

function showTooltip(nodeId, pointer, isEdge = false, edgeData = null) {
    const tooltip = document.getElementById("graph-tooltip");
    let content = "";

    if (isEdge && edgeData) {
        content = edgeData.title || "Connection";
    } else {
        const node = nodesDataset.get(nodeId);
        if (node) {
            content = node.title || node.label;
        }
    }

    if (content) {
        tooltip.innerHTML = content;

        // Use vis.js network's DOM positions
        const position = network.canvasToDOM(pointer);

        tooltip.style.left = `${position.x + 10}px`;
        tooltip.style.top = `${position.y + 10}px`;
        tooltip.style.display = "block";
    }
}

function hideTooltip() {
    document.getElementById("graph-tooltip").style.display = "none";
}

// Graph utility functions
// One pass over the ports instead of one pass per distinct service: this used
// to be O(services x ports) per graph render, and it counted the unfiltered
// data, so the tooltip disagreed with a filtered graph.
function countServiceInstances(counts, serviceName) {
    return counts.get(serviceName) || 0;
}

function countServices(hosts, filters) {
    const counts = new Map();
    hosts.forEach(host => {
        if (filters && !hostMatchesFilters(host, filters)) return;
        host.ports.forEach(port => {
            if (filters && !portMatchesFilters(port, filters)) return;
            const name = port.service.replace("?", "");
            counts.set(name, (counts.get(name) || 0) + 1);
        });
    });
    return counts;
}

function getConnectedHosts(serviceId) {
    return edgesDataset.get({
        filter: edge => edge.to === serviceId
    }).map(edge => edge.from);
}

function getConnectedServices(hostId) {
    return edgesDataset.get({
        filter: edge => edge.from === hostId
    }).map(edge => edge.to);
}

function formatNodeTooltip(host) {
    let tooltip = `<strong>${host.ip}</strong>`;

    if (host.hostname) {
        tooltip += `<br>${host.hostname}`;
    }

    tooltip += `<br>Open Ports: ${host.ports.length}`;

    if (host.ports.length > 0) {
        tooltip += "<br><br><strong>Ports:</strong><br>";

        host.ports.slice(0, 5).forEach(port => {
            tooltip += `${port.port}/${port.protocol} (${port.service})${port.comment ? ` - ${port.comment}` : ""}<br>`;
        });

        if (host.ports.length > 5) {
            tooltip += `... and ${host.ports.length - 5} more`;
        }
    }

    return tooltip;
}

function formatEdgeTooltip(ports) {
    let tooltip = "<strong>Ports:</strong><br>";

    ports.forEach(port => {
        tooltip += `${port.port}/${port.protocol} (${port.service})${port.comment ? ` - ${port.comment}` : ""}<br>`;
    });

    return tooltip;
}

// Only the previously highlighted ids are reset and every change goes out as
// one batched update; resetting both whole datasets per click meant O(nodes +
// edges) allocations and dataset writes every time a node was selected.
let highlightedNodes = [];
let highlightedEdges = [];

// A batched node update has to carry the node's value: vis recomputes the
// scaling range over the updated entries and throws without it.
function nodeUpdate(id, properties) {
    const node = nodesDataset.get(id);
    if (!node) return null;
    return Object.assign({ id: id, value: node.value }, properties);
}

function clearHighlight() {
    // ids from a previous graph must never be pushed into a rebuilt dataset:
    // vis would treat them as new nodes without a value and throw
    const nodeResets = highlightedNodes
        // null, not undefined: vis 10 throws on an undefined colour inside a
        // batched update, null puts the node back on its group default
        .map(id => nodesDataset && nodeUpdate(id, { color: null, font: null }))
        .filter(Boolean);
    const edgeResets = highlightedEdges
        .filter(edge => edgesDataset && edgesDataset.get(edge.id))
        .map(edge => ({ id: edge.id, color: null, width: edge.width }));

    if (nodeResets.length) nodesDataset.update(nodeResets);
    if (edgeResets.length) edgesDataset.update(edgeResets);

    highlightedNodes = [];
    highlightedEdges = [];
}

function highlightConnections(nodeId) {
    clearHighlight();

    const node = nodesDataset.get(nodeId);
    if (!node) return;

    const connectedNodes = new Set();
    const connectedEdges = [];

    const matches = node.type === "host"
        ? edge => edge.from === nodeId
        : node.type === "service"
            ? edge => edge.to === nodeId
            : null;

    if (matches) {
        edgesDataset.get({ filter: matches }).forEach(edge => {
            connectedNodes.add(node.type === "host" ? edge.to : edge.from);
            connectedEdges.push(edge);
        });
    }

    const nodeUpdates = [
        nodeUpdate(nodeId, {
            color: { border: "#8e44ad", background: "#9b59b6" },
            font: { color: "#000000", bold: true }
        })
    ].filter(Boolean);

    connectedNodes.forEach(id => {
        const update = nodeUpdate(id, {
            color: { border: "#16a085", background: "#1abc9c" },
            font: { bold: true }
        });
        if (update) nodeUpdates.push(update);
    });

    const edgeUpdates = connectedEdges.map(edge => ({
        id: edge.id,
        color: "#16a085",
        width: 2 * (edge.width || 1)
    }));

    if (nodeUpdates.length) nodesDataset.update(nodeUpdates);
    if (edgeUpdates.length) edgesDataset.update(edgeUpdates);

    highlightedNodes = nodeUpdates.map(update => update.id);
    highlightedEdges = connectedEdges.map(edge => ({ id: edge.id, width: edge.width }));
}

// Minimap functions
function initializeMinimap(nodes, edges) {
    const minimap = document.getElementById("graph-minimap");

    const minimapNodes = nodes.map(node => ({
        id: node.id,
        group: node.group
    }));

    const minimapEdges = edges.map(edge => ({
        from: edge.from,
        to: edge.to
    }));

    const minimapData = {
        nodes: new vis.DataSet(minimapNodes),
        edges: new vis.DataSet(minimapEdges)
    };

    minimapNetwork = new vis.Network(minimap, minimapData, {
        nodes: {
            shape: "dot",
            size: 3,
            font: {
                size: 0
            },
            borderWidth: 1
        },
        edges: {
            width: 1,
            smooth: false
        },
        interaction: {
            dragNodes: false,
            dragView: false,
            zoomView: false,
            selectable: false,
            tooltipDelay: 0
        },
        physics: {
            enabled: false
        },
        groups: {
            host: {
                color: "#3498db"
            },
            service: {
                color: "#2ecc71"
            },
            "up-only": {
                color: "#e67e22"
            },
            pinned: {
                color: "#9b59b6"
            }
        }
    });

    minimapNetwork.once("afterDrawing", function () {
        updateMinimap();
    });
}

function updateMinimap() {
    if (!minimapNetwork || !network) return;

    // it is built inside a hidden container, so it has to be measured again
    // the first time it is shown
    minimapNetwork.redraw();

    const scale = network.getScale();
    const position = network.getViewPosition();

    minimapNetwork.moveTo({
        position: position,
        scale: 0.2 * scale,
        animation: false
    });
}

// Export graph as PNG
function exportNetworkImage() {
    if (!network) {
        showError('Render the graph before exporting it as PNG');
        return;
    }

    const canvas = network.canvas.frame.canvas;
    const link = document.createElement('a');
    link.download = 'unitas-network.png';
    link.href = canvas.toDataURL('image/png').replace('image/png', 'image/octet-stream');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Save and restore views. They are kept in localStorage, an earlier version
// stored them in a variable nothing ever read.
const SAVED_VIEWS_KEY = 'unitas:graphViews';

function loadSavedViews() {
    try {
        savedViews = JSON.parse(localStorage.getItem(SAVED_VIEWS_KEY)) || {};
    } catch (error) {
        savedViews = {};
    }
    return savedViews;
}

function persistSavedViews() {
    try {
        localStorage.setItem(SAVED_VIEWS_KEY, JSON.stringify(savedViews));
    } catch (error) {
        showError('Could not store the view: browser storage is unavailable');
    }
}

function refreshSavedViewSelect() {
    const select = document.getElementById('saved-view-select');
    if (!select) return;

    const names = Object.keys(savedViews).sort();
    const previous = select.value;
    select.innerHTML = '';

    if (names.length === 0) {
        const option = document.createElement('option');
        option.value = '';
        option.textContent = 'No saved views';
        select.appendChild(option);
        return;
    }

    names.forEach(name => {
        const option = document.createElement('option');
        option.value = name;
        option.textContent = name;
        select.appendChild(option);
    });

    if (names.includes(previous)) {
        select.value = previous;
    }
}

function saveCurrentView() {
    if (!network) {
        showError('Render the graph before saving a view');
        return;
    }

    const name = prompt("Enter a name for this view:");
    if (!name) return;

    savedViews[name] = {
        position: network.getViewPosition(),
        scale: network.getScale(),
        pinnedNodes: Array.from(pinnedNodes),
        filter: {
            service: document.getElementById('service-filter').value,
            portMin: document.getElementById('port-min').value,
            portMax: document.getElementById('port-max').value,
            subnet: document.getElementById('subnet-filter').value,
            showUpHosts: document.getElementById('show-up-hosts').checked,
            showUncertain: document.getElementById('show-uncertain').checked,
            highlightTls: document.getElementById('highlight-tls').checked
        }
    };

    persistSavedViews();
    refreshSavedViewSelect();
    document.getElementById('saved-view-select').value = name;
    showToast(`View "${name}" saved`);
}

function loadSelectedView() {
    const select = document.getElementById('saved-view-select');
    const view = select && savedViews[select.value];
    if (!view) {
        showError('No saved view selected');
        return;
    }

    const filter = view.filter || {};
    if (filter.service !== undefined) document.getElementById('service-filter').value = filter.service;
    if (filter.portMin !== undefined) document.getElementById('port-min').value = filter.portMin;
    if (filter.portMax !== undefined) document.getElementById('port-max').value = filter.portMax;
    if (filter.subnet !== undefined) document.getElementById('subnet-filter').value = filter.subnet;
    if (filter.showUpHosts !== undefined) document.getElementById('show-up-hosts').checked = filter.showUpHosts;
    if (filter.showUncertain !== undefined) document.getElementById('show-uncertain').checked = filter.showUncertain;
    if (filter.highlightTls !== undefined) document.getElementById('highlight-tls').checked = filter.highlightTls;

    refreshGraph();

    if (network && view.position) {
        network.moveTo({
            position: view.position,
            scale: view.scale || 1,
            animation: false
        });
    }

    showToast(`View "${select.value}" loaded`);
}

function deleteSelectedView() {
    const select = document.getElementById('saved-view-select');
    const name = select && select.value;
    if (!name || !savedViews[name]) {
        showError('No saved view selected');
        return;
    }

    delete savedViews[name];
    persistSavedViews();
    refreshSavedViewSelect();
    showToast(`View "${name}" deleted`);
}

// Toggle physics simulation
function togglePhysics() {
    physicsEnabled = !physicsEnabled;
    network.setOptions({
        physics: {
            enabled: physicsEnabled
        }
    });
    document.getElementById('toggle-physics').textContent = physicsEnabled ? "Disable Physics" : "Enable Physics";
}

// Reset graph to fit all nodes
function fitGraph() {
    network.fit({
        animation: true
    });
}

// Pin/unpin nodes
function togglePinNode() {
    if (selectedNode) {
        if (pinnedNodes.has(selectedNode.id)) {
            pinnedNodes.delete(selectedNode.id);
            document.getElementById("pin-node").textContent = "Pin Node";
            const nodeData = { ...selectedNode };
            delete nodeData.fixed;
            nodesDataset.update(nodeData);
        } else {
            pinnedNodes.add(selectedNode.id);
            document.getElementById("pin-node").textContent = "Unpin Node";
            const position = network.getPositions([selectedNode.id])[selectedNode.id];
            nodesDataset.update({
                id: selectedNode.id,
                fixed: { x: true, y: true },
                x: position.x,
                y: position.y
            });
        }
    }
}

// Focus on selected node
function focusNode() {
    if (selectedNode) {
        network.focus(selectedNode.id, {
            scale: 1.5,
            animation: true
        });
    }
}

// Toggle minimap visibility. The minimap is hidden by default (see the
// stylesheet), previously it started visible and the first click hid it.
function toggleMinimap() {
    const minimap = document.getElementById("graph-minimap");
    const button = document.getElementById("toggle-minimap");
    const visible = minimap.classList.toggle('visible');

    if (button) {
        button.setAttribute('aria-pressed', visible ? 'true' : 'false');
    }
    if (visible) {
        updateMinimap();
    }
}

