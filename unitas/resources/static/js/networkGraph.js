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

    // Process hosts
    window.scanData.hosts.forEach((host) => {
        const hostId = nextId++;
        nodeIdMap[host.ip] = hostId;

        // Calculate value based on number of ports
        const portCount = host.ports.length;

        nodes.push({
            id: hostId,
            label: host.hostname || host.ip,
            title: formatNodeTooltip(host),
            group: "host",
            subnetGroup: getSubnetGroup(host.ip),
            type: "host",
            ip: host.ip,
            hostname: host.hostname,
            value: Math.max(10, Math.min(30, 10 + 2 * portCount)),
            ports: portCount,
            original: host
        });

        // Process services on this host
        const hostServices = {};

        host.ports.forEach((port) => {
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
                const serviceInstances = countServiceInstances(serviceName);

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
    if (window.scanData.hostsUp && document.getElementById("show-up-hosts").checked) {
        window.scanData.hostsUp.forEach((host) => {
            nodes.push({
                id: nextId++,
                label: host.ip,
                title: `<strong>${host.ip}</strong><br>Up: ${host.reason}`,
                group: "up-only",
                type: "up-host",
                ip: host.ip,
                reason: host.reason,
                value: 8,
                subnetGroup: getSubnetGroup(host.ip)
            });
        });
    }

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
            return {
                improvedLayout: true,
                randomSeed: 42
            };
        default:
            return {
                improvedLayout: true
            };
    }
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
function countServiceInstances(serviceName) {
    let count = 0;
    window.scanData.hosts.forEach(host => {
        host.ports.forEach(port => {
            if (port.service.replace("?", "") === serviceName) {
                count++;
            }
        });
    });
    return count;
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

function highlightConnections(nodeId) {
    // Reset all nodes and edges to default appearance
    nodesDataset.update(nodesDataset.get().map(node => ({
        id: node.id,
        color: undefined,
        font: undefined
    })));

    edgesDataset.update(edgesDataset.get().map(edge => ({
        id: edge.id,
        color: undefined,
        width: edge.originalWidth || edge.width
    })));

    // Get the selected node
    const node = nodesDataset.get(nodeId);
    const connectedNodes = new Set();
    const connectedEdges = new Set();

    if (node.type === "host") {
        // Find all edges from this host
        edgesDataset.get({
            filter: edge => edge.from === nodeId
        }).forEach(edge => {
            connectedNodes.add(edge.to);
            connectedEdges.add(edge.id);
        });
    } else if (node.type === "service") {
        // Find all edges to this service
        edgesDataset.get({
            filter: edge => edge.to === nodeId
        }).forEach(edge => {
            connectedNodes.add(edge.from);
            connectedEdges.add(edge.id);
        });
    }

    // Highlight the selected node
    nodesDataset.update({
        id: nodeId,
        color: {
            border: "#8e44ad",
            background: "#9b59b6"
        },
        font: {
            color: "#000000",
            bold: true
        }
    });

    // Highlight connected nodes
    connectedNodes.forEach(id => {
        nodesDataset.update({
            id: id,
            color: {
                border: "#16a085",
                background: "#1abc9c"
            },
            font: {
                bold: true
            }
        });
    });

    // Highlight connected edges
    connectedEdges.forEach(id => {
        const edge = edgesDataset.get(id);
        edgesDataset.update({
            id: id,
            color: "#16a085",
            width: 2 * (edge.width || 1),
            originalWidth: edge.width || 1
        });
    });
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
    if (!network) return;

    const canvas = network.canvas.frame.canvas;
    const link = document.createElement('a');
    link.download = 'unitas-network.png';
    link.href = canvas.toDataURL('image/png').replace('image/png', 'image/octet-stream');
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
}

// Save and restore views
function saveCurrentView() {
    if (!network) return;

    const name = prompt("Enter a name for this view:");

    if (name) {
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

        alert(`View "${name}" saved successfully!`);
    }
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

// Toggle minimap visibility
function toggleMinimap() {
    const minimap = document.getElementById("graph-minimap");
    if (minimap.style.display === 'none') {
        minimap.style.display = 'block';
        updateMinimap();
    } else {
        minimap.style.display = 'none';
    }
}

