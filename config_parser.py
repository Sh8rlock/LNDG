"""
LNDG - Config Parser
Parses YAML and JSON network topology configuration files.
Supports devices, connections, subnets, and security zones.
"""

import json
import os
import yaml

from network_model import (
    Device, Connection, Subnet, NetworkTopology
)


def parse_yaml(filepath):
    """Parse a YAML network topology file."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Config file not found: {filepath}")

    with open(filepath, 'r') as f:
        data = yaml.safe_load(f)

    return _build_topology(data, source=filepath)


def parse_json(filepath):
    """Parse a JSON network topology file."""
    if not os.path.exists(filepath):
        raise FileNotFoundError(f"Config file not found: {filepath}")

    with open(filepath, 'r') as f:
        data = json.load(f)

    return _build_topology(data, source=filepath)


def parse_config(filepath):
    """Auto-detect format and parse config file."""
    ext = os.path.splitext(filepath)[1].lower()
    if ext in ('.yaml', '.yml'):
        return parse_yaml(filepath)
    elif ext == '.json':
        return parse_json(filepath)
    else:
        # Try YAML first, then JSON
        try:
            return parse_yaml(filepath)
        except Exception:
            return parse_json(filepath)


def _build_topology(data, source="config"):
    """Build NetworkTopology from parsed config data."""
    network = data.get('network', data)
    name = network.get('name', 'Network Topology')
    topology = NetworkTopology(name=name)
    topology.metadata['source'] = source
    topology.metadata['source_type'] = 'config'

    # Parse subnets
    for subnet_data in network.get('subnets', []):
        subnet = Subnet(
            name=subnet_data.get('name', 'Unknown'),
            cidr=subnet_data.get('cidr', '0.0.0.0/0'),
            zone=subnet_data.get('zone', 'internal'),
            vlan=subnet_data.get('vlan'),
            description=subnet_data.get('description', '')
        )
        topology.add_subnet(subnet)

    # Parse devices
    for device_data in network.get('devices', []):
        device = Device(
            name=device_data.get('name', 'Unknown'),
            device_type=device_data.get('type', 'generic'),
            ip=device_data.get('ip'),
            subnet=device_data.get('subnet'),
            zone=device_data.get('zone', 'internal'),
            services=device_data.get('services', []),
            os_info=device_data.get('os'),
            mac=device_data.get('mac'),
            description=device_data.get('description', ''),
            risk_level=device_data.get('risk_level', 'low')
        )
        topology.add_device(device)

    # Parse connections
    for conn_data in network.get('connections', []):
        connection = Connection(
            source=conn_data.get('source', ''),
            target=conn_data.get('target', ''),
            protocol=conn_data.get('protocol'),
            port=conn_data.get('port'),
            bandwidth=conn_data.get('bandwidth'),
            encrypted=conn_data.get('encrypted', False),
            label=conn_data.get('label', ''),
            bidirectional=conn_data.get('bidirectional', True)
        )
        topology.add_connection(connection)

    return topology


def generate_sample_config(filepath="sample_network.yaml"):
    """Generate a sample YAML config file for reference."""
    sample = {
        'network': {
            'name': 'Sample Corporate Network',
            'subnets': [
                {'name': 'DMZ', 'cidr': '10.0.1.0/24', 'zone': 'dmz', 'vlan': 10,
                 'description': 'Internet-facing services'},
                {'name': 'Corporate', 'cidr': '10.0.2.0/24', 'zone': 'corporate', 'vlan': 20,
                 'description': 'Employee workstations and servers'},
                {'name': 'OT Network', 'cidr': '10.0.3.0/24', 'zone': 'ot', 'vlan': 30,
                 'description': 'Industrial control systems'},
            ],
            'devices': [
                {'name': 'Edge-FW', 'type': 'firewall', 'ip': '10.0.0.1',
                 'zone': 'internet', 'services': ['firewall'], 'description': 'Perimeter firewall'},
                {'name': 'Web-Server', 'type': 'server', 'ip': '10.0.1.10',
                 'subnet': 'DMZ', 'zone': 'dmz', 'services': ['HTTP', 'HTTPS'],
                 'os': 'Ubuntu 22.04', 'description': 'Public web server'},
                {'name': 'DC-01', 'type': 'server', 'ip': '10.0.2.10',
                 'subnet': 'Corporate', 'zone': 'corporate', 'services': ['AD', 'DNS', 'LDAP'],
                 'os': 'Windows Server 2022', 'description': 'Domain controller'},
                {'name': 'PLC-01', 'type': 'plc', 'ip': '10.0.3.10',
                 'subnet': 'OT Network', 'zone': 'ot', 'description': 'Process controller'},
            ],
            'connections': [
                {'source': 'Edge-FW', 'target': 'Web-Server', 'protocol': 'HTTPS', 'port': 443},
                {'source': 'Edge-FW', 'target': 'DC-01', 'protocol': 'VPN', 'encrypted': True},
                {'source': 'DC-01', 'target': 'PLC-01', 'protocol': 'Modbus',
                 'port': 502, 'encrypted': False, 'label': 'OT traffic'},
            ]
        }
    }

    with open(filepath, 'w') as f:
        yaml.dump(sample, f, default_flow_style=False, sort_keys=False)

    return filepath
