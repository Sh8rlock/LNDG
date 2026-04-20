"""
LNDG - Nmap XML Parser
Parses nmap scan results (XML format) into NetworkTopology.
Usage: nmap -sV -oX scan_results.xml 10.0.0.0/24
"""

import os
import xml.etree.ElementTree as ET

from network_model import Device, Connection, Subnet, NetworkTopology


# Well-known port to service mapping
PORT_SERVICE_MAP = {
    21: 'FTP', 22: 'SSH', 23: 'Telnet', 25: 'SMTP', 53: 'DNS',
    80: 'HTTP', 110: 'POP3', 135: 'RPC', 139: 'NetBIOS', 143: 'IMAP',
    443: 'HTTPS', 445: 'SMB', 502: 'Modbus', 636: 'LDAPS', 993: 'IMAPS',
    1433: 'MSSQL', 1521: 'Oracle', 3306: 'MySQL', 3389: 'RDP',
    5432: 'PostgreSQL', 5900: 'VNC', 8080: 'HTTP-Alt', 8443: 'HTTPS-Alt',
    44818: 'EtherNet/IP', 47808: 'BACnet', 20000: 'DNP3',
}

# Insecure services for risk flagging
INSECURE_SERVICES = {'FTP', 'Telnet', 'HTTP', 'VNC', 'NetBIOS', 'SMB'}

# OT/ICS protocol ports
OT_PORTS = {502, 44818, 47808, 20000, 2222, 18245, 4840}


def parse_nmap_xml(filepath):
    """Parse nmap XML output file into NetworkTopology."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Nmap XML file not found: {filepath}")

    tree = ET.parse(filepath)
    root = tree.getroot()

    topology = NetworkTopology(name="Nmap Scan Results")
    topology.metadata['source'] = filepath
    topology.metadata['source_type'] = 'nmap_xml'

    # Extract scan metadata
    scan_info = root.find('scaninfo')
    if scan_info is not None:
        topology.metadata['scan_type'] = scan_info.get('type', 'unknown')
        topology.metadata['protocol'] = scan_info.get('protocol', 'unknown')

    run_stats = root.find('runstats/finished')
    if run_stats is not None:
        topology.metadata['scan_time'] = run_stats.get('timestr', 'unknown')
        topology.metadata['elapsed'] = run_stats.get('elapsed', 'unknown')

    hosts_up = root.find('runstats/hosts')
    if hosts_up is not None:
        topology.metadata['hosts_up'] = int(hosts_up.get('up', 0))
        topology.metadata['hosts_down'] = int(hosts_up.get('down', 0))

    # Subnet tracking for auto-detection
    subnet_ips = {}

    # Parse each host
    for host in root.findall('host'):
        if host.find('status').get('state') != 'up':
            continue

        # Get IP address
        addr_elem = host.find("address[@addrtype='ipv4']")
        if addr_elem is None:
            continue
        ip = addr_elem.get('addr')

        # Get MAC address
        mac_elem = host.find("address[@addrtype='mac']")
        mac = mac_elem.get('addr') if mac_elem is not None else None
        vendor = mac_elem.get('vendor', '') if mac_elem is not None else ''

        # Get hostname
        hostname_elem = host.find('hostnames/hostname')
        hostname = hostname_elem.get('name') if hostname_elem is not None else ip

        # Get OS info
        os_info = None
        os_elem = host.find('os/osmatch')
        if os_elem is not None:
            os_info = os_elem.get('name', 'Unknown')

        # Parse open ports and services
        services = []
        open_ports = []
        has_ot_services = False
        has_insecure = False

        ports_elem = host.find('ports')
        if ports_elem is not None:
            for port in ports_elem.findall('port'):
                state = port.find('state')
                if state is not None and state.get('state') == 'open':
                    port_num = int(port.get('portid'))
                    protocol = port.get('protocol', 'tcp')
                    open_ports.append(port_num)

                    service_elem = port.find('service')
                    if service_elem is not None:
                        svc_name = service_elem.get('name', '')
                        svc_product = service_elem.get('product', '')
                        service_str = f"{svc_name}/{port_num}"
                        if svc_product:
                            service_str += f" ({svc_product})"
                        services.append(service_str)
                    else:
                        svc_name = PORT_SERVICE_MAP.get(port_num, f'port-{port_num}')
                        services.append(f"{svc_name}/{port_num}")

                    if port_num in OT_PORTS:
                        has_ot_services = True
                    if PORT_SERVICE_MAP.get(port_num, '') in INSECURE_SERVICES:
                        has_insecure = True

        # Determine device type from services and OS
        device_type = _infer_device_type(services, os_info, open_ports, vendor)

        # Determine zone
        zone = 'ot' if has_ot_services else 'corporate'

        # Determine risk level
        risk_level = 'low'
        if has_insecure and has_ot_services:
            risk_level = 'critical'
        elif has_ot_services:
            risk_level = 'high'
        elif has_insecure:
            risk_level = 'medium'
        elif len(open_ports) > 10:
            risk_level = 'medium'

        # Track subnet
        subnet_prefix = '.'.join(ip.split('.')[:3]) + '.0/24'
        if subnet_prefix not in subnet_ips:
            subnet_ips[subnet_prefix] = []
        subnet_ips[subnet_prefix].append(hostname)

        # Create device
        device = Device(
            name=hostname,
            device_type=device_type,
            ip=ip,
            subnet=subnet_prefix,
            zone=zone,
            services=services,
            os_info=os_info,
            mac=mac,
            description=f"Vendor: {vendor}" if vendor else None,
            risk_level=risk_level
        )
        topology.add_device(device)

    # Auto-create subnets
    for cidr, devices in subnet_ips.items():
        has_ot = any(
            topology.devices[d].zone == 'ot' for d in devices if d in topology.devices
        )
        subnet = Subnet(
            name=cidr,
            cidr=cidr,
            zone='ot' if has_ot else 'corporate',
            description=f"Auto-detected subnet ({len(devices)} hosts)"
        )
        topology.add_subnet(subnet)

    # Infer connections from shared subnets
    _infer_connections(topology)

    return topology


def _infer_device_type(services, os_info, ports, vendor):
    """Infer device type from service fingerprint."""
    services_lower = ' '.join(services).lower()
    os_lower = (os_info or '').lower()
    vendor_lower = (vendor or '').lower()

    # OT/ICS devices
    if any(p in ports for p in OT_PORTS):
        if 502 in ports:
            return 'plc'
        return 'scada'

    # Network infrastructure
    if any(kw in vendor_lower for kw in ['cisco', 'juniper', 'arista', 'fortinet', 'palo alto']):
        if any(p in ports for p in [179, 520, 8291]):
            return 'router'
        return 'switch'

    # Firewalls
    if any(kw in services_lower for kw in ['firewall', 'palo', 'fortinet']):
        return 'firewall'

    # Servers
    if 'server' in os_lower or any(p in ports for p in [80, 443, 3306, 1433, 5432, 1521, 8080]):
        if any(p in ports for p in [3306, 1433, 5432, 1521]):
            return 'database'
        return 'server'

    # Printers
    if any(p in ports for p in [9100, 515, 631]) or 'print' in vendor_lower:
        return 'printer'

    # Workstations
    if 'windows' in os_lower and 'server' not in os_lower:
        return 'workstation'

    if 3389 in ports and len(ports) < 5:
        return 'workstation'

    return 'generic'


def _infer_connections(topology):
    """Infer connections between devices on same subnet."""
    subnet_devices = {}
    for name, device in topology.devices.items():
        if device.subnet:
            if device.subnet not in subnet_devices:
                subnet_devices[device.subnet] = []
            subnet_devices[device.subnet].append(name)

    for subnet, devices in subnet_devices.items():
        # Find gateway/router/firewall in subnet
        gateways = [d for d in devices
                     if topology.devices[d].device_type in ('router', 'firewall', 'switch')]

        if gateways:
            # Connect all devices to gateway
            gw = gateways[0]
            for d in devices:
                if d != gw:
                    connection = Connection(
                        source=gw,
                        target=d,
                        label=f"Subnet {subnet}"
                    )
                    topology.add_connection(connection)
        elif len(devices) > 1:
            # Star topology from first device
            hub = devices[0]
            for d in devices[1:]:
                connection = Connection(
                    source=hub,
                    target=d,
                    label=f"Subnet {subnet}"
                )
                topology.add_connection(connection)


def generate_sample_nmap_xml(filepath="sample_nmap_scan.xml"):
    """Generate a sample nmap XML file for testing."""
    xml_content = """<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -sV -oX scan.xml 10.0.0.0/24" start="1713400000">
<scaninfo type="syn" protocol="tcp" numservices="1000" services="1-1024"/>

<host starttime="1713400001" endtime="1713400010">
  <status state="up"/>
  <address addr="10.0.0.1" addrtype="ipv4"/>
  <address addr="00:1A:2B:3C:4D:01" addrtype="mac" vendor="Cisco"/>
  <hostnames><hostname name="edge-fw-01" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="Palo Alto"/></port>
    <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH"/></port>
  </ports>
  <os><osmatch name="Palo Alto PAN-OS 10.x" accuracy="95"/></os>
</host>

<host starttime="1713400001" endtime="1713400010">
  <status state="up"/>
  <address addr="10.0.1.10" addrtype="ipv4"/>
  <address addr="00:1A:2B:3C:4D:10" addrtype="mac" vendor="Dell"/>
  <hostnames><hostname name="web-srv-01" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="nginx"/></port>
    <port protocol="tcp" portid="443"><state state="open"/><service name="https" product="nginx"/></port>
    <port protocol="tcp" portid="22"><state state="open"/><service name="ssh" product="OpenSSH"/></port>
  </ports>
  <os><osmatch name="Linux 5.x" accuracy="90"/></os>
</host>

<host starttime="1713400001" endtime="1713400010">
  <status state="up"/>
  <address addr="10.0.2.10" addrtype="ipv4"/>
  <address addr="00:1A:2B:3C:4D:20" addrtype="mac" vendor="Dell"/>
  <hostnames><hostname name="dc-01" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="53"><state state="open"/><service name="dns" product="Microsoft DNS"/></port>
    <port protocol="tcp" portid="88"><state state="open"/><service name="kerberos"/></port>
    <port protocol="tcp" portid="389"><state state="open"/><service name="ldap" product="Active Directory"/></port>
    <port protocol="tcp" portid="445"><state state="open"/><service name="smb" product="Windows SMB"/></port>
    <port protocol="tcp" portid="636"><state state="open"/><service name="ldaps"/></port>
    <port protocol="tcp" portid="3389"><state state="open"/><service name="rdp"/></port>
  </ports>
  <os><osmatch name="Windows Server 2022" accuracy="92"/></os>
</host>

<host starttime="1713400001" endtime="1713400010">
  <status state="up"/>
  <address addr="10.0.3.10" addrtype="ipv4"/>
  <address addr="00:1A:2B:3C:4D:30" addrtype="mac" vendor="Siemens"/>
  <hostnames><hostname name="plc-reactor-01" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="502"><state state="open"/><service name="modbus"/></port>
    <port protocol="tcp" portid="80"><state state="open"/><service name="http" product="Siemens S7"/></port>
  </ports>
  <os><osmatch name="Siemens SIMATIC S7-1500" accuracy="85"/></os>
</host>

<host starttime="1713400001" endtime="1713400010">
  <status state="up"/>
  <address addr="10.0.3.20" addrtype="ipv4"/>
  <address addr="00:1A:2B:3C:4D:31" addrtype="mac" vendor="Rockwell"/>
  <hostnames><hostname name="hmi-control-01" type="PTR"/></hostnames>
  <ports>
    <port protocol="tcp" portid="44818"><state state="open"/><service name="EtherNet-IP"/></port>
    <port protocol="tcp" portid="80"><state state="open"/><service name="http"/></port>
    <port protocol="tcp" portid="443"><state state="open"/><service name="https"/></port>
  </ports>
  <os><osmatch name="Rockwell FactoryTalk" accuracy="80"/></os>
</host>

<runstats><finished time="1713400060" timestr="Thu Apr 18 2026" elapsed="60"/>
<hosts up="5" down="251" total="256"/></runstats>
</nmaprun>"""

    with open(filepath, 'w') as f:
        f.write(xml_content)

    return filepath

