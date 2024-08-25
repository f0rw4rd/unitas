mport glob
import xml.etree.ElementTree as ET
from xml.etree.ElementTree import ParseError
import pickle
import os

class PortDetails:
    def __init__(self, port, protocol, state, service=None):
        self.port = port
        self.protocol = protocol
        self.state = state
        self.service = service

    def __str__(self):
        return f"{self.port}/{self.protocol}({self.service})"

    def to_dict(self):
        return {
            "port": self.port,
            "protocol": self.protocol,
            "state": self.state,
            "service": self.service
        }

    @classmethod
    def from_dict(cls, data):
        return cls(data['port'], data['protocol'], data['state'], data['service'])

class HostScanData:
    def __init__(self, ip):
        self.ip = ip
        self.hostname = None
        self.ports = []

    def overwrite_service(self, old_service, new_service) -> bool:
        # only replace if service has more information                
        if "?" in old_service and not "?" in new_service:
            return True
        # longer service name the better
        if not "?" in new_service and len(new_service) > len(old_service):
            return True
        return False

    def add_port(self, port: int, protocol: str, state: str, service: str="unknown?"):
        for p in self.ports: 
            if p.port == port and p.protocol == protocol: 
                if self.overwrite_service(p.service, service):
                    p.service = service 
                return
        self.ports.append(PortDetails(port, protocol, state, service))

    def set_hostname(self, hostname):
        self.hostname = hostname
    
    def get_sorted_ports(self):
        # Sort ports by protocol and then by port number (assuming ports are stored as strings, convert to int for sorting)
        sorted_ports = sorted(self.ports, key=lambda p: (p.protocol, int(p.port)))
        return sorted_ports

    def merge(self, other):
        """Merge another HostScanData object into this one."""
        if self.ip != other.ip:
            raise ValueError("Cannot merge hosts with different IPs")
        self.hostname = self.hostname or other.hostname
        existing_ports = {(port.port, port.protocol): port for port in self.ports}
        new_ports = []
        for port in other.ports:
            key = (port.port, port.protocol)
            if key not in existing_ports:
                self.ports.append(port)
                new_ports.append(port)
            elif not existing_ports[key].service and port.service:
                existing_ports[key].service = port.service
            elif self.overwrite_service(existing_ports[key].service, port.service):
                existing_ports[key].service = port.service
        return new_ports

    def __str__(self):
        ports_str = ", ".join(str(port) for port in self.ports)
        return f"{self.ip} ({self.hostname}): {ports_str}"

    def to_dict(self):
        return {
            "ip": self.ip,
            "hostname": self.hostname,
            "ports": [port.to_dict() for port in self.ports]
        }

    def to_markdown_rows(self):
        return [f"|{self.ip}|{str(x)}|       |       |" for x in self.get_sorted_ports()]

    @classmethod
    def from_dict(cls, data):
        host = cls(data['ip'])
        host.hostname = data['hostname']
        for port_data in data['ports']:
            host.ports.append(PortDetails.from_dict(port_data))
        return host

def save_to_file(hosts, filename='.state.pkl'):
    """Save the dictionary of HostScanData objects to a file using pickle."""
    with open(filename, 'wb') as file:
        pickle.dump(hosts, file)

def load_from_file(filename='.state.pkl') -> dict:
    """Load the dictionary of HostScanData objects from a file using pickle."""
    if not os.path.exists(filename):
        print("File not found. Using empty state.")
        return {}
    with open(filename, 'rb') as file:
        return pickle.load(file)

def glob_files(directory, extensions):
    """ Glob files in the specified directory with given extensions. """
    files = []
    for ext in extensions:
        files.extend(glob.glob(f"{directory}/**/*.{ext}", recursive=True))
    return files


def parse_nessus(file_path):
    """Parse a .nessus file to extract hosts and open ports."""
    tree = ET.parse(file_path)
    root = tree.getroot()
    data = {}

    for block in root.findall('.//ReportHost'):
        ip = block.attrib.get('name')
        host = HostScanData(ip=ip)

        # Set hostname if available
        hostname = block.find(".//tag[@name='host-fqdn']")
        if hostname is not None:
            host.set_hostname(hostname.text)
        
        for item in block.findall(".//ReportItem[@pluginFamily='Service detection']"):
            port = item.attrib.get('port')
            protocol = item.attrib.get('protocol')            
            service = item.attrib.get('svc_name') 
            if "TLS" in item.attrib.get("pluginName") or "SSL" in item.attrib.get("pluginName"):
                service += "/tls"
            state = "open"
            host.add_port(port, protocol, state, service)

        for item in block.findall(".//ReportItem[@pluginFamily='Port scanners']"):            
            port = item.attrib.get('port')          
            if port == "0": # host scan
                continue   
            protocol = item.attrib.get('protocol')
            service = item.attrib.get('svc_name')
            if "?" not in service: # append a ? for just port scans
                service += "?"
            state = "open"
            host.add_port(port, protocol, state, service)

        data[ip] = host

    return data

def parse_nmap(file_path):
    """Parse an .nmap file to extract hosts and open ports."""
    tree = ET.parse(file_path)
    root = tree.getroot()
    data = {}

    for host in root.findall('.//host'):
        # Check if host is up
        status = host.find('.//status')
        if status is not None and status.attrib.get('state') == 'up':
            address = host.find('.//address')
            if address is not None:
                host_ip = address.attrib.get('addr')
                h = HostScanData(ip=host_ip)

                for port in host.findall('.//port'):
                    protocol = port.attrib.get("protocol")
                    portid = port.attrib.get("portid")    
                    if portid == "443":
                        pass                
                    state = port.find('.//state').attrib.get('state')
                    service_element = port.find('.//service')
                    if service_element is not None:
                        service = service_element.attrib.get('name')
                        if service_element.attrib.get("method") == "table":
                            service += "?"
                        if service_element.attrib.get("tunnel", "none") == "ssl":
                            service += "/tls"
                    else:
                        service = "unknown?"                        
                    if state == 'open':
                        h.add_port(portid, protocol, state, service)

                data[host_ip] = h

    return data

def merge_host_data(global_state, new_data):
    new_hosts = []
    updated_hosts = {}

    for ip, host_data in new_data.items():
        if ip in global_state:
            new_ports = global_state[ip].merge(host_data)
            if new_ports:
                updated_hosts[ip] = new_ports
        else:
            global_state[ip] = host_data
            new_hosts.append(host_data)

    return new_hosts, updated_hosts


def print_changes(new_hosts, updated_hosts):
    if new_hosts:
        print("New hosts added:")
        for host in new_hosts:
            print(host)

    if updated_hosts:
        print("Hosts with new ports:")
        for ip, ports in updated_hosts.items():
            ports_str = ", ".join(str(port) for port in ports)
            print(f"{ip} {ports_str}")            
                

def parse_file(parse_function, file: str, global_state: dict):
    print()
    print(f"Trying to load file {file}")
    try: 
        scan_results = parse_function(file)
        new_hosts, updated_hosts = merge_host_data(global_state, scan_results)
        print_changes(new_hosts, updated_hosts)
    except ParseError:
        print("Could not load, invalid XML")

def main():
    directory = 'scans2'  # Adjust this path
    nessus_files = glob_files(directory, ['nessus'])
    nmap_files = glob_files(directory, ['xml'])  # Adjust if your nmap files have different extensions

    global_state = load_from_file()

    # Process Nessus files
    for file in nessus_files:
        parse_file(parse_nessus, file, global_state)

    # Process Nmap files
    for file in nmap_files:
        parse_file(parse_nmap, file, global_state)

    # Output results
    print("|IP|Port|Status|Comment")
    print("|--|--|--|---|")
    for k, v in global_state.items():
        for row in v.to_markdown_rows():
            print(row)

    save_to_file(global_state)

    
if __name__ == "__main__":
    main()
