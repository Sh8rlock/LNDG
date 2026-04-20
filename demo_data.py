"""
LNDG - Demo Data Generator
Creates a realistic enterprise + OT/ICS network topology for demonstration.
Simulates a chemical manufacturing facility with corporate IT and industrial control systems.
"""

from network_model import Device, Connection, Subnet, NetworkTopology


def generate_demo_topology():
    """Generate a full enterprise + OT/ICS demo topology."""
    topology = NetworkTopology(name="Chevron Phillips Chemical - Demo Network")
    topology.metadata['source'] = 'demo'
    topology.metadata['source_type'] = 'demo'
    topology.metadata['description'] = (
        'Simulated enterprise and OT/ICS network topology for a chemical '
        'manufacturing facility. Includes corporate IT, DMZ, cloud, '
        'management, and OT/ICS security zones.'
    )

    # ── Subnets ──────────────────────────────────────────────
    subnets = [
        Subnet('Internet', '0.0.0.0/0', 'internet', description='External/untrusted network'),
        Subnet('DMZ', '10.10.1.0/24', 'dmz', vlan=10,
               description='Internet-facing services'),
        Subnet('Corporate-Servers', '10.10.2.0/24', 'corporate', vlan=20,
               description='Internal servers and domain controllers'),
        Subnet('Corporate-Users', '10.10.3.0/24', 'corporate', vlan=30,
               description='Employee workstations'),
        Subnet('Management', '10.10.4.0/24', 'management', vlan=40,
               description='Network management and monitoring'),
        Subnet('Cloud-Transit', '10.10.5.0/24', 'cloud', vlan=50,
               description='Azure/AWS connectivity'),
        Subnet('OT-Level3', '10.20.1.0/24', 'ot', vlan=100,
               description='OT Level 3 - Site operations and historian'),
        Subnet('OT-Level2', '10.20.2.0/24', 'ot', vlan=200,
               description='OT Level 2 - HMI and supervisory control'),
        Subnet('OT-Level1', '10.20.3.0/24', 'ot', vlan=300,
               description='OT Level 1 - PLCs and basic control'),
        Subnet('OT-Level0', '10.20.4.0/24', 'ot', vlan=400,
               description='OT Level 0 - Field devices and sensors'),
    ]
    for s in subnets:
        topology.add_subnet(s)

    # ── Internet Zone ────────────────────────────────────────
    devices_internet = [
        Device('ISP-Router', 'router', '1.1.1.1', 'Internet', 'internet',
               services=['BGP'], description='ISP upstream router'),
        Device('Cloud-Azure', 'cloud', '52.168.0.1', 'Internet', 'cloud',
               services=['Azure AD', 'Intune', 'Sentinel', 'Defender'],
               description='Azure cloud services'),
    ]

    # ── DMZ Zone ─────────────────────────────────────────────
    devices_dmz = [
        Device('Edge-Firewall', 'firewall', '10.10.0.1', 'DMZ', 'dmz',
               services=['Firewall', 'VPN', 'IPS'],
               description='Palo Alto PA-5250 perimeter firewall',
               risk_level='low'),
        Device('Web-Server-01', 'server', '10.10.1.10', 'DMZ', 'dmz',
               services=['HTTPS/443', 'HTTP/80'], os_info='Ubuntu 22.04 LTS',
               description='Public-facing web application server',
               risk_level='medium'),
        Device('Mail-Gateway', 'server', '10.10.1.20', 'DMZ', 'dmz',
               services=['SMTP/25', 'SMTPS/465'],
               description='Email security gateway (Proofpoint)',
               risk_level='medium'),
        Device('VPN-Concentrator', 'server', '10.10.1.30', 'DMZ', 'dmz',
               services=['IPSec/500', 'SSL-VPN/443'],
               description='Remote access VPN (GlobalProtect)',
               risk_level='low'),
        Device('IDS-Sensor-01', 'ids', '10.10.1.40', 'DMZ', 'dmz',
               services=['SPAN', 'Snort'],
               description='Network IDS sensor monitoring DMZ traffic'),
    ]

    # ── Corporate Zone ───────────────────────────────────────
    devices_corp = [
        Device('Core-Switch', 'switch', '10.10.2.1', 'Corporate-Servers', 'corporate',
               services=['VLAN', 'STP', 'LACP'],
               description='Cisco Catalyst 9300 core switch'),
        Device('DC-01', 'server', '10.10.2.10', 'Corporate-Servers', 'corporate',
               services=['AD/389', 'DNS/53', 'Kerberos/88', 'LDAPS/636'],
               os_info='Windows Server 2022',
               description='Primary domain controller (Entra ID synced)'),
        Device('DC-02', 'server', '10.10.2.11', 'Corporate-Servers', 'corporate',
               services=['AD/389', 'DNS/53', 'Kerberos/88'],
               os_info='Windows Server 2022',
               description='Secondary domain controller'),
        Device('SIEM-Splunk', 'server', '10.10.2.20', 'Corporate-Servers', 'corporate',
               services=['Splunk/8089', 'Syslog/514', 'HEC/8088'],
               os_info='RHEL 8',
               description='Splunk Enterprise SIEM (500GB/day)'),
        Device('File-Server', 'server', '10.10.2.30', 'Corporate-Servers', 'corporate',
               services=['SMB/445', 'NFS/2049'],
               os_info='Windows Server 2022',
               description='Corporate file shares'),
        Device('DB-Server-01', 'database', '10.10.2.40', 'Corporate-Servers', 'corporate',
               services=['MSSQL/1433', 'TDS/1433'],
               os_info='Windows Server 2022',
               description='SQL Server for business applications'),
        Device('Workstation-Eng-01', 'workstation', '10.10.3.10', 'Corporate-Users', 'corporate',
               services=['RDP/3389'], os_info='Windows 11 Enterprise',
               description='Engineering workstation (CrowdStrike agent)'),
        Device('Workstation-Eng-02', 'workstation', '10.10.3.11', 'Corporate-Users', 'corporate',
               services=['RDP/3389'], os_info='Windows 11 Enterprise',
               description='Engineering workstation (CrowdStrike agent)'),
        Device('Printer-Floor2', 'printer', '10.10.3.50', 'Corporate-Users', 'corporate',
               services=['IPP/631', 'JetDirect/9100'],
               description='HP LaserJet Enterprise'),
    ]

    # ── Management Zone ──────────────────────────────────────
    devices_mgmt = [
        Device('NMS-SolarWinds', 'server', '10.10.4.10', 'Management', 'management',
               services=['SNMP/161', 'HTTPS/443', 'Syslog/514'],
               os_info='Windows Server 2022',
               description='SolarWinds network monitoring'),
        Device('Vuln-Scanner', 'server', '10.10.4.20', 'Management', 'management',
               services=['Nessus/8834', 'HTTPS/443'],
               os_info='Ubuntu 22.04',
               description='Tenable Nessus vulnerability scanner'),
        Device('Jump-Server', 'server', '10.10.4.30', 'Management', 'management',
               services=['RDP/3389', 'SSH/22'],
               os_info='Windows Server 2022',
               description='Privileged access jump box (PAM-controlled)'),
    ]

    # ── OT/ICS Zone (Purdue Model) ──────────────────────────
    devices_ot = [
        # Level 3.5 - IT/OT DMZ
        Device('OT-Firewall', 'firewall', '10.20.0.1', 'OT-Level3', 'ot',
               services=['Firewall', 'IPS'],
               description='Fortinet FortiGate IT/OT boundary firewall',
               risk_level='low'),

        # Level 3 - Site Operations
        Device('Historian-Server', 'historian', '10.20.1.10', 'OT-Level3', 'ot',
               services=['OSIsoft-PI/5450', 'HTTPS/443', 'SQL/1433'],
               os_info='Windows Server 2019',
               description='OSIsoft PI historian (process data archive)',
               risk_level='medium'),
        Device('OT-AD-Server', 'server', '10.20.1.20', 'OT-Level3', 'ot',
               services=['AD/389', 'DNS/53'],
               os_info='Windows Server 2019',
               description='OT domain controller (isolated from corporate AD)',
               risk_level='medium'),
        Device('OT-Patch-Server', 'server', '10.20.1.30', 'OT-Level3', 'ot',
               services=['WSUS/8530'],
               os_info='Windows Server 2019',
               description='OT patch management (WSUS)',
               risk_level='low'),

        # Level 2 - Supervisory Control
        Device('SCADA-Server', 'scada', '10.20.2.10', 'OT-Level2', 'ot',
               services=['OPC-UA/4840', 'Modbus-GW/502', 'HTTPS/443'],
               os_info='Windows Server 2019',
               description='Honeywell Experion SCADA server',
               risk_level='high'),
        Device('HMI-Reactor-01', 'hmi', '10.20.2.20', 'OT-Level2', 'ot',
               services=['VNC/5900', 'HTTP/80'],
               os_info='Windows 10 LTSC',
               description='Reactor control HMI panel',
               risk_level='high'),
        Device('HMI-Distill-01', 'hmi', '10.20.2.21', 'OT-Level2', 'ot',
               services=['VNC/5900', 'HTTP/80'],
               os_info='Windows 10 LTSC',
               description='Distillation unit HMI panel',
               risk_level='high'),
        Device('EWS-01', 'engineering', '10.20.2.30', 'OT-Level2', 'ot',
               services=['SSH/22', 'Modbus/502'],
               os_info='Windows 10',
               description='Engineering workstation (PLC programming)',
               risk_level='high'),

        # Level 1 - Basic Control
        Device('PLC-Reactor-01', 'plc', '10.20.3.10', 'OT-Level1', 'ot',
               services=['Modbus/502', 'EtherNet-IP/44818'],
               os_info='Siemens S7-1500',
               description='Reactor process PLC',
               risk_level='critical'),
        Device('PLC-Reactor-02', 'plc', '10.20.3.11', 'OT-Level1', 'ot',
               services=['Modbus/502'],
               os_info='Allen-Bradley ControlLogix',
               description='Reactor safety PLC (SIL-2)',
               risk_level='critical'),
        Device('PLC-Distill-01', 'plc', '10.20.3.20', 'OT-Level1', 'ot',
               services=['Modbus/502', 'EtherNet-IP/44818'],
               os_info='Siemens S7-1200',
               description='Distillation column PLC',
               risk_level='critical'),
        Device('RTU-Tank-01', 'plc', '10.20.3.30', 'OT-Level1', 'ot',
               services=['DNP3/20000', 'Modbus/502'],
               description='Tank farm RTU',
               risk_level='critical'),

        # Level 0 - Field Devices
        Device('Sensor-Temp-R1', 'iot', '10.20.4.10', 'OT-Level0', 'ot',
               services=['Modbus/502'],
               description='Reactor 1 temperature transmitter',
               risk_level='high'),
        Device('Sensor-Press-R1', 'iot', '10.20.4.11', 'OT-Level0', 'ot',
               services=['HART'],
               description='Reactor 1 pressure transmitter',
               risk_level='high'),
        Device('Sensor-Flow-D1', 'iot', '10.20.4.20', 'OT-Level0', 'ot',
               services=['Modbus/502'],
               description='Distillation flow meter',
               risk_level='high'),
        Device('Valve-Act-R1', 'iot', '10.20.4.30', 'OT-Level0', 'ot',
               services=['HART', 'Modbus/502'],
               description='Reactor 1 control valve actuator',
               risk_level='critical'),
    ]

    # Add all devices
    for device_list in [devices_internet, devices_dmz, devices_corp,
                        devices_mgmt, devices_ot]:
        for device in device_list:
            topology.add_device(device)

    # ── Connections ──────────────────────────────────────────
    connections = [
        # Internet → DMZ
        Connection('ISP-Router', 'Edge-Firewall', 'BGP', 179, '1Gbps', label='WAN uplink'),
        Connection('Cloud-Azure', 'Edge-Firewall', 'IPSec', 500, encrypted=True, label='Site-to-site VPN'),

        # DMZ internal
        Connection('Edge-Firewall', 'Web-Server-01', 'HTTPS', 443, label='Inbound web traffic'),
        Connection('Edge-Firewall', 'Mail-Gateway', 'SMTP', 25, label='Inbound email'),
        Connection('Edge-Firewall', 'VPN-Concentrator', 'SSL-VPN', 443, encrypted=True, label='Remote access'),
        Connection('IDS-Sensor-01', 'Edge-Firewall', 'SPAN', label='Traffic mirroring', bidirectional=False),

        # DMZ → Corporate
        Connection('Edge-Firewall', 'Core-Switch', 'Trunk', label='Inter-VLAN routing'),
        Connection('Mail-Gateway', 'DC-01', 'LDAPS', 636, encrypted=True, label='Directory lookup'),

        # Corporate core
        Connection('Core-Switch', 'DC-01', 'Trunk', label='Server VLAN'),
        Connection('Core-Switch', 'DC-02', 'Trunk', label='Server VLAN'),
        Connection('Core-Switch', 'SIEM-Splunk', 'Trunk', label='Server VLAN'),
        Connection('Core-Switch', 'File-Server', 'Trunk', label='Server VLAN'),
        Connection('Core-Switch', 'DB-Server-01', 'Trunk', label='Server VLAN'),
        Connection('Core-Switch', 'Workstation-Eng-01', 'Trunk', label='User VLAN'),
        Connection('Core-Switch', 'Workstation-Eng-02', 'Trunk', label='User VLAN'),
        Connection('Core-Switch', 'Printer-Floor2', 'Trunk', label='User VLAN'),

        # DC replication
        Connection('DC-01', 'DC-02', 'AD-Repl', 389, label='AD replication'),

        # Management
        Connection('Core-Switch', 'NMS-SolarWinds', 'Trunk', label='Mgmt VLAN'),
        Connection('Core-Switch', 'Vuln-Scanner', 'Trunk', label='Mgmt VLAN'),
        Connection('Core-Switch', 'Jump-Server', 'Trunk', label='Mgmt VLAN'),
        Connection('NMS-SolarWinds', 'SIEM-Splunk', 'Syslog', 514, label='Alert forwarding', bidirectional=False),

        # Log collection
        Connection('DC-01', 'SIEM-Splunk', 'WinRM', 5985, label='Log collection', bidirectional=False),
        Connection('Edge-Firewall', 'SIEM-Splunk', 'Syslog', 514, label='FW logs', bidirectional=False),

        # Cloud
        Connection('DC-01', 'Cloud-Azure', 'HTTPS', 443, encrypted=True, label='Azure AD Connect sync'),

        # IT/OT Boundary (critical segmentation point)
        Connection('Core-Switch', 'OT-Firewall', 'Trunk', label='IT/OT boundary (restricted)'),

        # OT Level 3
        Connection('OT-Firewall', 'Historian-Server', 'HTTPS', 443, label='Historian access'),
        Connection('OT-Firewall', 'OT-AD-Server', 'LDAPS', 636, encrypted=True, label='OT auth'),
        Connection('OT-Firewall', 'OT-Patch-Server', 'HTTPS', 8530, label='Patch distribution'),
        Connection('Historian-Server', 'SIEM-Splunk', 'Syslog', 514, label='OT logs to SIEM', bidirectional=False),

        # OT Level 3 → Level 2
        Connection('Historian-Server', 'SCADA-Server', 'OPC-UA', 4840, label='Process data collection'),
        Connection('OT-AD-Server', 'SCADA-Server', 'LDAP', 389, label='OT authentication'),

        # OT Level 2
        Connection('SCADA-Server', 'HMI-Reactor-01', 'OPC-UA', 4840, label='Reactor control'),
        Connection('SCADA-Server', 'HMI-Distill-01', 'OPC-UA', 4840, label='Distillation control'),
        Connection('EWS-01', 'SCADA-Server', 'SSH', 22, label='Engineering access'),

        # OT Level 2 → Level 1
        Connection('HMI-Reactor-01', 'PLC-Reactor-01', 'Modbus', 502, label='Reactor control loop'),
        Connection('HMI-Reactor-01', 'PLC-Reactor-02', 'Modbus', 502, label='Safety interlock'),
        Connection('HMI-Distill-01', 'PLC-Distill-01', 'Modbus', 502, label='Distillation control'),
        Connection('EWS-01', 'PLC-Reactor-01', 'Modbus', 502, label='PLC programming'),
        Connection('EWS-01', 'PLC-Distill-01', 'EtherNet/IP', 44818, label='PLC programming'),
        Connection('SCADA-Server', 'RTU-Tank-01', 'DNP3', 20000, label='Tank monitoring'),

        # OT Level 1 → Level 0
        Connection('PLC-Reactor-01', 'Sensor-Temp-R1', 'Modbus', 502, label='Temperature reading'),
        Connection('PLC-Reactor-01', 'Sensor-Press-R1', 'HART', label='Pressure reading'),
        Connection('PLC-Reactor-01', 'Valve-Act-R1', 'Modbus', 502, label='Valve control'),
        Connection('PLC-Distill-01', 'Sensor-Flow-D1', 'Modbus', 502, label='Flow reading'),
    ]

    for conn in connections:
        topology.add_connection(conn)

    return topology


def generate_small_demo():
    """Generate a smaller demo for quick testing."""
    topology = NetworkTopology(name="Small Office Network - Demo")
    topology.metadata['source'] = 'demo_small'
    topology.metadata['source_type'] = 'demo'

    # Subnets
    topology.add_subnet(Subnet('WAN', '0.0.0.0/0', 'internet'))
    topology.add_subnet(Subnet('LAN', '192.168.1.0/24', 'corporate', vlan=1))
    topology.add_subnet(Subnet('Servers', '192.168.2.0/24', 'corporate', vlan=2))

    # Devices
    devices = [
        Device('Internet', 'cloud', '0.0.0.0', 'WAN', 'internet'),
        Device('Firewall', 'firewall', '192.168.0.1', 'WAN', 'dmz',
               services=['Firewall', 'NAT', 'VPN']),
        Device('Switch-01', 'switch', '192.168.1.1', 'LAN', 'corporate',
               services=['VLAN', 'STP']),
        Device('PC-01', 'workstation', '192.168.1.10', 'LAN', 'corporate',
               os_info='Windows 11'),
        Device('PC-02', 'workstation', '192.168.1.11', 'LAN', 'corporate',
               os_info='Windows 11'),
        Device('Server-01', 'server', '192.168.2.10', 'Servers', 'corporate',
               services=['HTTP', 'HTTPS', 'SSH'], os_info='Ubuntu 22.04'),
        Device('Printer', 'printer', '192.168.1.50', 'LAN', 'corporate'),
    ]
    for d in devices:
        topology.add_device(d)

    # Connections
    conns = [
        Connection('Internet', 'Firewall', 'WAN', label='Internet uplink'),
        Connection('Firewall', 'Switch-01', 'Trunk', label='LAN'),
        Connection('Switch-01', 'PC-01', 'Ethernet', label='Access port'),
        Connection('Switch-01', 'PC-02', 'Ethernet', label='Access port'),
        Connection('Switch-01', 'Server-01', 'Ethernet', label='Server port'),
        Connection('Switch-01', 'Printer', 'Ethernet', label='Access port'),
    ]
    for c in conns:
        topology.add_connection(c)

    return topology

