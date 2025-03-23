// Network analysis tools
function runAnalysis() {
    const analysisType = document.getElementById('analysis-type').value;
    const resultContainer = document.getElementById('analysis-result');
    const contentContainer = document.getElementById('analysis-content');

    if (analysisType === "none") {
        resultContainer.classList.add("hidden");
        return;
    }

    resultContainer.classList.remove("hidden");
    let content = "";

    switch (analysisType) {
        case "common-services":
            content = findCommonServices();
            break;
        case "segments":
            content = identifyNetworkSegments();
            break;
        case "unusual":
            content = findUnusualPorts();
            break;
        case "connectivity":
            content = findMostConnectedHosts();
            break;
    }

    contentContainer.innerHTML = content;
}

function findCommonServices() {
    const services = {};

    scanData.hosts.forEach(host => {
        const uniqueServices = new Set();

        host.ports.forEach(port => {
            const serviceName = port.service.replace("?", "");
            uniqueServices.add(serviceName);
        });

        uniqueServices.forEach(service => {
            services[service] = (services[service] || 0) + 1;
        });
    });

    const commonServices = Object.entries(services)
        .sort((a, b) => b[1] - a[1])
        .filter(([_, count]) => count > 1);

    if (commonServices.length === 0) {
        return "<p>No common services found across multiple hosts.</p>";
    }

    let result = "<p>Services found on multiple hosts:</p><ul>";

    commonServices.forEach(([service, count]) => {
        const percentage = Math.round((count / scanData.hosts.length) * 100);
        result += `<li><strong>${service}</strong>: Found on ${count} hosts (${percentage}%)</li>`;
    });

    result += "</ul>";
    return result;
}

function identifyNetworkSegments() {
    let result = "<p>Identified network segments:</p><ul>";

    Object.entries(subnetGroups)
        .sort((a, b) => b[1].hosts.size - a[1].hosts.size)
        .forEach(([subnet, data]) => {
            result += `<li><strong>${subnet}.0/24</strong>: ${data.hosts.size} hosts`;

            if (data.services.size > 0) {
                result += `, ${data.services.size} services`;

                const topServices = Array.from(data.services).slice(0, 3);
                if (topServices.length > 0) {
                    result += ` (${topServices.join(", ")}${data.services.size > 3 ? "..." : ""})`;
                }
            }

            result += "</li>";
        });

    result += "</ul>";
    return result;
}

function findUnusualPorts() {
    const portCounts = {};
    const highPorts = [];
    const nonStandardPorts = [];

    scanData.hosts.forEach(host => {
        host.ports.forEach(port => {
            const portNum = parseInt(port.port);

            // Count port occurrences
            portCounts[portNum] = (portCounts[portNum] || 0) + 1;

            // Track high ports
            if (portNum > 10000) {
                highPorts.push({
                    ip: host.ip,
                    hostname: host.hostname,
                    port: port.port,
                    protocol: port.protocol,
                    service: port.service
                });
            }

            // Track non-standard service ports
            const standardPorts = {
                'http': [80, 8080],
                'https': [443, 8443],
                'ssh': [22],
                'ftp': [21],
                'smtp': [25],
                'dns': [53],
                'rdp': [3389]
            };

            const service = port.service.replace("?", "");

            if (standardPorts[service] && !standardPorts[service].includes(portNum)) {
                nonStandardPorts.push({
                    ip: host.ip,
                    hostname: host.hostname,
                    port: port.port,
                    protocol: port.protocol,
                    service: port.service,
                    standardPorts: standardPorts[service].join(", ")
                });
            }
        });
    });

    // Find ports that appear only once
    const uncommonPorts = Object.entries(portCounts)
        .filter(([_, count]) => count === 1)
        .map(([port, _]) => parseInt(port))
        .sort((a, b) => a - b);

    let result = "";

    if (highPorts.length > 0) {
        result += "<p><strong>Unusual high ports (>10000):</strong></p><ul>";

        highPorts.slice(0, 10).forEach(port => {
            result += `<li>${port.ip} - ${port.port}/${port.protocol} (${port.service})</li>`;
        });

        if (highPorts.length > 10) {
            result += `<li>...and ${highPorts.length - 10} more</li>`;
        }

        result += "</ul>";
    }

    if (nonStandardPorts.length > 0) {
        result += "<p><strong>Services on non-standard ports:</strong></p><ul>";

        nonStandardPorts.forEach(port => {
            result += `<li>${port.ip} - ${port.service} on port ${port.port} (standard: ${port.standardPorts})</li>`;
        });

        result += "</ul>";
    }

    if (uncommonPorts.length > 0) {
        result += "<p><strong>Uncommon ports (found on only one host):</strong></p>";
        result += `<p>${uncommonPorts.slice(0, 20).join(", ")}${uncommonPorts.length > 20 ? "..." : ""}</p>`;
    }

    if (result === "") {
        result = "<p>No unusual ports detected.</p>";
    }

    return result;
}

function findMostConnectedHosts() {
    const hosts = {};

    scanData.hosts.forEach(host => {
        hosts[host.ip] = {
            ip: host.ip,
            hostname: host.hostname,
            ports: host.ports.length,
            services: new Set(host.ports.map(port => port.service.replace("?", "")))
        };
    });

    const sortedHosts = Object.values(hosts).sort((a, b) => b.ports - a.ports);

    let result = "<p><strong>Hosts by connectivity (number of open ports):</strong></p><ul>";

    sortedHosts.slice(0, 10).forEach(host => {
        result += `<li><strong>${host.ip}</strong>${host.hostname ? ` (${host.hostname})` : ""}: ${host.ports} ports, ${host.services.size} unique services</li>`;
    });

    if (sortedHosts.length > 10) {
        result += `<li>...and ${sortedHosts.length - 10} more hosts</li>`;
    }

    result += "</ul>";
    return result;
}
