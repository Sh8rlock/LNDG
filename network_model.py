"""
LNDG - Network Model
Custom graph model for network topology (no NetworkX dependency).
Supports devices, connections, subnets, and security zones.
"""


class Device:
    """Represents a network device (node)."""

    def __init__(self, name, device_type="generic", ip=None, subnet=None,
                 zone="internal", services=None, os_info=None, mac=None,
                 description=None, risk_level="low"):
        self.name = name
        self.device_type = device_type
        self.ip = ip
        self.subnet = subnet
        self.zone = zone
        self.services = services or []
        self.os_info = os_info
        self.mac = mac
        self.description = description
        self.risk_level = risk_level
        self.connections = []

    def to_dict(self):
        return {
            'name': self.name,
            'type': self.device_type,
            'ip': self.ip,
            'subnet': self.subnet,
            'zone': self.zone,
            'services': self.services,
            'os': self.os_info,
            'mac': self.mac,
            'description': self.description,
            'risk_level': self.risk_level
        }


class Connection:
    """Represents a network connection (edge)."""

    def __init__(self, source, target, protocol=None, port=None,
                 bandwidth=None, encrypted=False, label=None, bidirectional=True):
        self.source = source
        self.target = target
        self.protocol = protocol
        self.port = port
        self.bandwidth = bandwidth
        self.encrypted = encrypted
        self.label = label or ""
        self.bidirectional = bidirectional

    def to_dict(self):
        return {
            'source': self.source,
            'target': self.target,
            'protocol': self.protocol,
            'port': self.port,
            'bandwidth': self.bandwidth,
            'encrypted': self.encrypted,
            'label': self.label,
            'bidirectional': self.bidirectional
        }


class Subnet:
    """Represents a network subnet."""

    def __init__(self, name, cidr, zone="internal", vlan=None, description=None):
        self.name = name
        self.cidr = cidr
        self.zone = zone
        self.vlan = vlan
        self.description = description
        self.devices = []

    def to_dict(self):
        return {
            'name': self.name,
            'cidr': self.cidr,
            'zone': self.zone,
            'vlan': self.vlan,
            'description': self.description,
            'device_count': len(self.devices)
        }


ZONE_CONFIG = {
    'internet':    {'color': '#DC2626', 'bg': '#FEE2E2', 'label': 'Internet / Untrusted', 'trust': 0},
    'dmz':         {'color': '#EA580C', 'bg': '#FED7AA', 'label': 'DMZ', 'trust': 1},
    'corporate':   {'color': '#2563EB', 'bg': '#DBEAFE', 'label': 'Corporate LAN', 'trust': 3},
    'management':  {'color': '#7C3AED', 'bg': '#EDE9FE', 'label': 'Management', 'trust': 4},
    'ot':          {'color': '#DC2626', 'bg': '#FEF3C7', 'label': 'OT / ICS Zone', 'trust': 5},
    'cloud':       {'color': '#0891B2', 'bg': '#CFFAFE', 'label': 'Cloud (Azure/AWS)', 'trust': 2},
    'internal':    {'color': '#059669', 'bg': '#D1FAE5', 'label': 'Internal', 'trust': 3},
}

DEVICE_MARKERS = {
    'firewall':    {'marker': 's', 'size': 700, 'icon': '[FW]'},
    'router':      {'marker': 'D', 'size': 600, 'icon': '[R]'},
    'switch':      {'marker': 'h', 'size': 550, 'icon': '[SW]'},
    'server':      {'marker': 's', 'size': 600, 'icon': '[SRV]'},
    'workstation':  {'marker': 'o', 'size': 400, 'icon': '[WS]'},
    'plc':         {'marker': '^', 'size': 500, 'icon': '[PLC]'},
    'hmi':         {'marker': 'p', 'size': 500, 'icon': '[HMI]'},
    'scada':       {'marker': '*', 'size': 700, 'icon': '[SCADA]'},
    'cloud':       {'marker': 'o', 'size': 600, 'icon': '[CLD]'},
    'iot':         {'marker': 'v', 'size': 350, 'icon': '[IoT]'},
    'printer':     {'marker': '8', 'size': 350, 'icon': '[PRN]'},
    'database':    {'marker': 's', 'size': 550, 'icon': '[DB]'},
    'ids':         {'marker': 'D', 'size': 500, 'icon': '[IDS]'},
    'historian':   {'marker': 's', 'size': 550, 'icon': '[HIST]'},
    'engineering': {'marker': 'p', 'size': 500, 'icon': '[EWS]'},
    'generic':     {'marker': 'o', 'size': 400, 'icon': '[?]'},
}


class NetworkTopology:
    """Complete network topology graph."""

    def __init__(self, name="Network Topology"):
        self.name = name
        self.devices = {}
        self.connections = []
        self.subnets = {}
        self.metadata = {
            'created_by': 'LNDG',
            'version': '1.0.0',
        }

    def add_device(self, device):
        """Add a device to the topology."""
        self.devices[device.name] = device
        if device.subnet and device.subnet in self.subnets:
            self.subnets[device.subnet].devices.append(device.name)
        return device

    def add_connection(self, connection):
        """Add a connection between devices."""
        self.connections.append(connection)
        if connection.source in self.devices:
            self.devices[connection.source].connections.append(connection.target)
        if connection.bidirectional and connection.target in self.devices:
            self.devices[connection.target].connections.append(connection.source)
        return connection

    def add_subnet(self, subnet):
        """Add a subnet to the topology."""
        self.subnets[subnet.name] = subnet
        return subnet

    def get_devices_by_zone(self, zone):
        """Get all devices in a security zone."""
        return {k: v for k, v in self.devices.items() if v.zone == zone}

    def get_devices_by_type(self, device_type):
        """Get all devices of a specific type."""
        return {k: v for k, v in self.devices.items() if v.device_type == device_type}

    def get_zones(self):
        """Get all unique zones in the topology."""
        return list(set(d.zone for d in self.devices.values()))

    def get_stats(self):
        """Get topology statistics."""
        zones = {}
        types = {}
        for d in self.devices.values():
            zones[d.zone] = zones.get(d.zone, 0) + 1
            types[d.device_type] = types.get(d.device_type, 0) + 1

        return {
            'total_devices': len(self.devices),
            'total_connections': len(self.connections),
            'total_subnets': len(self.subnets),
            'devices_by_zone': zones,
            'devices_by_type': types,
            'zones': self.get_zones(),
        }

    def to_dict(self):
        """Export topology as dictionary."""
        return {
            'name': self.name,
            'metadata': self.metadata,
            'stats': self.get_stats(),
            'subnets': {k: v.to_dict() for k, v in self.subnets.items()},
            'devices': {k: v.to_dict() for k, v in self.devices.items()},
            'connections': [c.to_dict() for c in self.connections],
        }
