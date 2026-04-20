"""
LNDG - Report Generator
Generates professional HTML and JSON reports from network topology data.
Includes topology statistics, device inventory, security zone analysis,
and risk assessment.
"""

import json
import os
from datetime import datetime

from network_model import ZONE_CONFIG, DEVICE_MARKERS, NetworkTopology


def generate_html_report(topology, diagram_paths=None, output_path="lndg_report.html"):
    """Generate a comprehensive HTML report."""
    stats = topology.get_stats()
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Risk summary
    risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for device in topology.devices.values():
        risk_counts[device.risk_level] = risk_counts.get(device.risk_level, 0) + 1

    # Security findings
    findings = _analyze_security(topology)

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>LNDG Report - {topology.name}</title>
<style>
    * {{ margin: 0; padding: 0; box-sizing: border-box; }}
    body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
           background: #0f172a; color: #e2e8f0; line-height: 1.6; }}
    .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
    .header {{ background: linear-gradient(135deg, #1e293b, #334155);
              padding: 30px; border-radius: 12px; margin-bottom: 24px;
              border: 1px solid #475569; }}
    .header h1 {{ font-size: 28px; color: #f8fafc; margin-bottom: 8px; }}
    .header .subtitle {{ color: #94a3b8; font-size: 14px; }}
    .header .meta {{ display: flex; gap: 20px; margin-top: 12px; flex-wrap: wrap; }}
    .header .meta span {{ background: #1e293b; padding: 4px 12px; border-radius: 6px;
                         font-size: 12px; color: #cbd5e1; border: 1px solid #475569; }}

    .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 16px; margin-bottom: 24px; }}
    .stat-card {{ background: #1e293b; padding: 20px; border-radius: 10px;
                 border: 1px solid #334155; text-align: center; }}
    .stat-card .value {{ font-size: 36px; font-weight: 700; }}
    .stat-card .label {{ font-size: 12px; color: #94a3b8; text-transform: uppercase;
                        letter-spacing: 1px; margin-top: 4px; }}
    .stat-card.critical .value {{ color: #ef4444; }}
    .stat-card.high .value {{ color: #f97316; }}
    .stat-card.medium .value {{ color: #eab308; }}
    .stat-card.info .value {{ color: #3b82f6; }}
    .stat-card.green .value {{ color: #22c55e; }}

    .section {{ background: #1e293b; border-radius: 10px; padding: 24px;
               margin-bottom: 24px; border: 1px solid #334155; }}
    .section h2 {{ font-size: 18px; color: #f8fafc; margin-bottom: 16px;
                  padding-bottom: 8px; border-bottom: 2px solid #3b82f6; }}
    .section h3 {{ font-size: 15px; color: #cbd5e1; margin: 16px 0 8px; }}

    table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
    th {{ background: #334155; color: #e2e8f0; padding: 10px 14px; text-align: left;
         font-size: 12px; text-transform: uppercase; letter-spacing: 0.5px; }}
    td {{ padding: 10px 14px; border-bottom: 1px solid #334155; font-size: 13px; }}
    tr:hover {{ background: #334155; }}

    .badge {{ display: inline-block; padding: 2px 8px; border-radius: 4px;
             font-size: 11px; font-weight: 600; text-transform: uppercase; }}
    .badge-critical {{ background: #450a0a; color: #fca5a5; border: 1px solid #dc2626; }}
    .badge-high {{ background: #431407; color: #fdba74; border: 1px solid #ea580c; }}
    .badge-medium {{ background: #422006; color: #fde047; border: 1px solid #eab308; }}
    .badge-low {{ background: #052e16; color: #86efac; border: 1px solid #22c55e; }}

    .zone-badge {{ display: inline-block; padding: 2px 10px; border-radius: 4px;
                  font-size: 11px; font-weight: 600; }}

    .finding {{ background: #0f172a; border-radius: 8px; padding: 16px;
               margin-bottom: 12px; border-left: 4px solid; }}
    .finding.critical {{ border-color: #dc2626; }}
    .finding.high {{ border-color: #ea580c; }}
    .finding.medium {{ border-color: #eab308; }}
    .finding.low {{ border-color: #22c55e; }}
    .finding .title {{ font-weight: 600; margin-bottom: 4px; }}
    .finding .detail {{ font-size: 13px; color: #94a3b8; }}

    .diagram-container {{ text-align: center; margin: 16px 0; }}
    .diagram-container img {{ max-width: 100%; border-radius: 8px;
                             border: 1px solid #475569; }}

    .footer {{ text-align: center; padding: 20px; color: #64748b; font-size: 12px; }}
</style>
</head>
<body>
<div class="container">

<div class="header">
    <h1>LNDG Network Topology Report</h1>
    <div class="subtitle">{topology.name}</div>
    <div class="meta">
        <span>Generated: {timestamp}</span>
        <span>Source: {topology.metadata.get('source_type', 'unknown')}</span>
        <span>LNDG v1.0.0</span>
    </div>
</div>

<div class="grid">
    <div class="stat-card info">
        <div class="value">{stats['total_devices']}</div>
        <div class="label">Total Devices</div>
    </div>
    <div class="stat-card green">
        <div class="value">{stats['total_connections']}</div>
        <div class="label">Connections</div>
    </div>
    <div class="stat-card info">
        <div class="value">{stats['total_subnets']}</div>
        <div class="label">Subnets</div>
    </div>
    <div class="stat-card info">
        <div class="value">{len(stats['zones'])}</div>
        <div class="label">Security Zones</div>
    </div>
    <div class="stat-card critical">
        <div class="value">{risk_counts.get('critical', 0)}</div>
        <div class="label">Critical Risk</div>
    </div>
    <div class="stat-card high">
        <div class="value">{risk_counts.get('high', 0)}</div>
        <div class="label">High Risk</div>
    </div>
    <div class="stat-card medium">
        <div class="value">{risk_counts.get('medium', 0)}</div>
        <div class="label">Medium Risk</div>
    </div>
    <div class="stat-card green">
        <div class="value">{risk_counts.get('low', 0)}</div>
        <div class="label">Low Risk</div>
    </div>
</div>
"""

    # Diagram images
    if diagram_paths:
        html += '<div class="section">\n<h2>Network Diagrams</h2>\n'
        for path in diagram_paths:
            if path.endswith(('.png', '.svg')):
                basename = os.path.basename(path)
                html += f'''<div class="diagram-container">
    <h3>{basename}</h3>
    <img src="{path}" alt="{basename}">
</div>\n'''
        html += '</div>\n'

    # Device inventory
    html += '''<div class="section">
<h2>Device Inventory</h2>
<table>
<tr><th>Device</th><th>Type</th><th>IP Address</th><th>Zone</th>
    <th>Services</th><th>OS</th><th>Risk</th></tr>
'''
    for name, device in sorted(topology.devices.items()):
        zone_config = ZONE_CONFIG.get(device.zone, ZONE_CONFIG['internal'])
        risk_class = device.risk_level
        services = ', '.join(device.services[:4])
        if len(device.services) > 4:
            services += f' +{len(device.services) - 4}'

        html += f'''<tr>
    <td><strong>{name}</strong></td>
    <td>{device.device_type.capitalize()}</td>
    <td>{device.ip or 'N/A'}</td>
    <td><span class="zone-badge" style="background:{zone_config['color']}22;
        color:{zone_config['color']};border:1px solid {zone_config['color']}">{device.zone.upper()}</span></td>
    <td>{services or 'N/A'}</td>
    <td>{device.os_info or 'N/A'}</td>
    <td><span class="badge badge-{risk_class}">{risk_class.upper()}</span></td>
</tr>\n'''

    html += '</table>\n</div>\n'

    # Subnet summary
    html += '''<div class="section">
<h2>Subnet Summary</h2>
<table>
<tr><th>Subnet</th><th>CIDR</th><th>Zone</th><th>VLAN</th>
    <th>Devices</th><th>Description</th></tr>
'''
    for name, subnet in sorted(topology.subnets.items()):
        zone_config = ZONE_CONFIG.get(subnet.zone, ZONE_CONFIG['internal'])
        device_count = len([d for d in topology.devices.values() if d.subnet == name])
        html += f'''<tr>
    <td><strong>{name}</strong></td>
    <td>{subnet.cidr}</td>
    <td><span class="zone-badge" style="background:{zone_config['color']}22;
        color:{zone_config['color']};border:1px solid {zone_config['color']}">{subnet.zone.upper()}</span></td>
    <td>{subnet.vlan or 'N/A'}</td>
    <td>{device_count}</td>
    <td>{subnet.description or 'N/A'}</td>
</tr>\n'''

    html += '</table>\n</div>\n'

    # Connection matrix
    html += '''<div class="section">
<h2>Connection Details</h2>
<table>
<tr><th>Source</th><th>Target</th><th>Protocol</th><th>Port</th>
    <th>Encrypted</th><th>Label</th></tr>
'''
    for conn in topology.connections:
        encrypted_badge = ('<span class="badge badge-low">YES</span>'
                          if conn.encrypted
                          else '<span class="badge badge-medium">NO</span>')
        html += f'''<tr>
    <td>{conn.source}</td>
    <td>{conn.target}</td>
    <td>{conn.protocol or 'N/A'}</td>
    <td>{conn.port or 'N/A'}</td>
    <td>{encrypted_badge}</td>
    <td>{conn.label or 'N/A'}</td>
</tr>\n'''

    html += '</table>\n</div>\n'

    # Security findings
    if findings:
        html += '<div class="section">\n<h2>Security Findings</h2>\n'
        for finding in findings:
            html += f'''<div class="finding {finding['severity']}">
    <div class="title">{finding['title']}</div>
    <div class="detail">{finding['detail']}</div>
    <div class="detail" style="margin-top:4px"><strong>Affected:</strong> {finding['affected']}</div>
</div>\n'''
        html += '</div>\n'

    # Zone distribution
    html += '<div class="section">\n<h2>Zone Distribution</h2>\n'
    html += '<table><tr><th>Zone</th><th>Trust Level</th><th>Devices</th><th>Percentage</th></tr>\n'
    total = stats['total_devices']
    for zone, count in sorted(stats['devices_by_zone'].items(),
                               key=lambda x: ZONE_CONFIG.get(x[0], {}).get('trust', 3)):
        zone_config = ZONE_CONFIG.get(zone, ZONE_CONFIG['internal'])
        pct = (count / total * 100) if total > 0 else 0
        html += f'''<tr>
    <td><span class="zone-badge" style="background:{zone_config['color']}22;
        color:{zone_config['color']};border:1px solid {zone_config['color']}">{zone_config['label']}</span></td>
    <td>{zone_config['trust']}/5</td>
    <td>{count}</td>
    <td>{pct:.1f}%</td>
</tr>\n'''
    html += '</table>\n</div>\n'

    # Footer
    html += f'''
<div class="footer">
    LNDG - Linux Network Diagram Generator v1.0.0 | Report generated {timestamp}<br>
    Author: Larry Odeyemi | github.com/Sh8rlock/LNDG
</div>

</div>
</body>
</html>'''

    with open(output_path, 'w') as f:
        f.write(html)

    return output_path


def generate_json_report(topology, output_path="lndg_report.json"):
    """Generate a JSON report with full topology data."""
    stats = topology.get_stats()

    risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for device in topology.devices.values():
        risk_counts[device.risk_level] = risk_counts.get(device.risk_level, 0) + 1

    findings = _analyze_security(topology)

    report = {
        'report': {
            'tool': 'LNDG',
            'version': '1.0.0',
            'generated': datetime.now().isoformat(),
            'author': 'Larry Odeyemi',
        },
        'topology': topology.to_dict(),
        'risk_summary': risk_counts,
        'security_findings': findings,
        'statistics': stats,
    }

    with open(output_path, 'w') as f:
        json.dump(report, f, indent=2, default=str)

    return output_path


def _analyze_security(topology):
    """Analyze topology for security issues."""
    findings = []

    # Check for unencrypted OT connections
    unencrypted_ot = []
    for conn in topology.connections:
        src = topology.devices.get(conn.source)
        tgt = topology.devices.get(conn.target)
        if src and tgt and src.zone == 'ot' and tgt.zone == 'ot':
            if not conn.encrypted:
                unencrypted_ot.append(f"{conn.source} → {conn.target} ({conn.protocol or 'unknown'})")

    if unencrypted_ot:
        findings.append({
            'severity': 'high',
            'title': 'Unencrypted OT/ICS Communications',
            'detail': (f'{len(unencrypted_ot)} OT connections lack encryption. '
                      'Industrial protocols (Modbus, DNP3) transmit in cleartext, '
                      'enabling man-in-the-middle attacks on process control data.'),
            'affected': '; '.join(unencrypted_ot[:5]),
            'mitre': 'T1557 - Adversary-in-the-Middle',
        })

    # Check for insecure services
    insecure_devices = []
    insecure_services_set = {'FTP', 'Telnet', 'HTTP', 'VNC', 'NetBIOS'}
    for name, device in topology.devices.items():
        for svc in device.services:
            svc_name = svc.split('/')[0].upper()
            if svc_name in insecure_services_set:
                insecure_devices.append(f"{name} ({svc})")
                break

    if insecure_devices:
        findings.append({
            'severity': 'medium',
            'title': 'Insecure Services Detected',
            'detail': (f'{len(insecure_devices)} devices running insecure/unencrypted services. '
                      'These services transmit credentials and data in cleartext.'),
            'affected': '; '.join(insecure_devices[:5]),
            'mitre': 'T1040 - Network Sniffing',
        })

    # Check for critical risk devices
    critical_devices = [name for name, d in topology.devices.items()
                       if d.risk_level == 'critical']
    if critical_devices:
        findings.append({
            'severity': 'critical',
            'title': 'Critical Risk Devices Identified',
            'detail': (f'{len(critical_devices)} devices classified as critical risk. '
                      'These are typically PLCs, safety controllers, or devices with '
                      'direct physical process control that require enhanced protection.'),
            'affected': '; '.join(critical_devices[:5]),
            'mitre': 'T0831 - Manipulation of Control',
        })

    # Check for IT/OT boundary
    it_ot_connections = []
    for conn in topology.connections:
        src = topology.devices.get(conn.source)
        tgt = topology.devices.get(conn.target)
        if src and tgt:
            if (src.zone == 'ot') != (tgt.zone == 'ot'):
                if src.device_type != 'firewall' and tgt.device_type != 'firewall':
                    it_ot_connections.append(f"{conn.source} → {conn.target}")

    if it_ot_connections:
        findings.append({
            'severity': 'high',
            'title': 'IT/OT Boundary Connections Without Firewall',
            'detail': (f'{len(it_ot_connections)} connections cross the IT/OT boundary '
                      'without passing through a firewall. Per NIST 800-82, all IT/OT '
                      'traffic should be filtered and monitored.'),
            'affected': '; '.join(it_ot_connections[:5]),
            'mitre': 'T0886 - Remote Services',
        })

    # Check for flat network (too many devices in one subnet)
    for name, subnet in topology.subnets.items():
        device_count = len([d for d in topology.devices.values() if d.subnet == name])
        if device_count > 10:
            findings.append({
                'severity': 'medium',
                'title': f'Large Subnet: {name}',
                'detail': (f'Subnet {name} ({subnet.cidr}) contains {device_count} devices. '
                          'Consider microsegmentation to limit lateral movement.'),
                'affected': name,
                'mitre': 'T1570 - Lateral Tool Transfer',
            })

    # Check for devices without services listed
    unknown_devices = [name for name, d in topology.devices.items() if not d.services]
    if unknown_devices:
        findings.append({
            'severity': 'low',
            'title': 'Devices With Unknown Services',
            'detail': (f'{len(unknown_devices)} devices have no services documented. '
                      'Unknown services indicate incomplete asset inventory.'),
            'affected': '; '.join(unknown_devices[:5]),
            'mitre': 'T1046 - Network Service Discovery',
        })

    return findings

