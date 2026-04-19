# LNDG - Linux Network Diagram Generator

A Python-based network topology visualization tool that generates professional network diagrams from configuration files, nmap scan results, and packet captures. Designed for security engineers and network architects who need clear, security-zone-aware documentation without active network scanning.

## Why Config-Based (Not Active Scanning)?

Active scanning (ARP/ICMP/SYN probes) mirrors adversary reconnaissance (MITRE ATT&CK T1046) and can crash legacy OT/ICS devices. LNDG takes the enterprise approach: parse existing data sources and generate diagrams safely.

## Features

- **YAML/JSON Config Parser** - Define devices, subnets, connections, and security zones
- **Nmap XML Parser** - Import authorized scan results and auto-generate topology
- **PCAP Integration** - Feed packet captures (from LNPS) to infer network connections
- **Security Zone Mapping** - Color-coded zones: Internet, DMZ, Corporate, Management, Cloud, OT
- **Risk Visualization** - Border-coded risk levels: Critical, High, Medium, Low
- **Three Layout Modes** - Zone, Hierarchical, and Purdue Model (ICS/OT)
- **Light and Dark Themes** - Professional output for reports and presentations
- **Multiple Output Formats** - PNG and SVG diagram export
- **HTML and JSON Reports** - Detailed security findings with device inventory
- **Demo Mode** - Pre-built chemical plant network (35 devices, 6 zones)

## Quick Start

git clone https://github.com/Sh8rlock/LNDG.git
cd LNDG
pip install -r requirements.txt
python run_lndg.py --demo

## Demo Output

Devices created: 35
Connections mapped: 44
Subnets: 10
Security Zones: 6
Risk Distribution: 5 Critical | 7 High | 4 Medium | 19 Low
Diagrams generated: 7 (3 layouts x 2 themes + SVG)
Reports generated: HTML + JSON

## Usage

python run_lndg.py --config network.yaml
python run_lndg.py --nmap scan_results.xml
python run_lndg.py --config network.yaml --layout zone
python run_lndg.py --config network.yaml --layout hierarchical
python run_lndg.py --config network.yaml --layout purdue
python run_lndg.py --config network.yaml --theme dark
python run_lndg.py --config network.yaml --format svg
python run_lndg.py --demo

## Layout Modes

| Layout | Best For |
|--------|----------|
| Zone | Security zone visualization - groups devices by trust level |
| Hierarchical | Network architecture - tiers from cloud/firewall down to endpoints |
| Purdue | OT/ICS environments - Purdue Model levels 0-5 for industrial control systems |

## Security Zones

| Zone | Color (Light) | Color (Dark) | Purpose |
|------|---------------|--------------|---------|
| Internet | Red | Dark Red | External/untrusted traffic |
| DMZ | Orange | Dark Orange | Public-facing services |
| Corporate | Blue | Dark Blue | Business network |
| Management | Purple | Dark Purple | Admin and monitoring |
| Cloud | Cyan | Dark Cyan | Cloud services (AWS/Azure) |
| OT | Yellow | Dark Yellow | Industrial control systems |

## Project Structure

LNDG/
├── run_lndg.py           # CLI entry point
├── network_model.py      # Device, Connection, Subnet, NetworkTopology classes
├── config_parser.py      # YAML/JSON topology config reader
├── nmap_parser.py        # Nmap XML scan result parser
├── demo_data.py          # Chemical plant demo network (35 devices)
├── diagram_engine.py     # Matplotlib-based diagram renderer
├── report_generator.py   # HTML + JSON report generation
├── requirements.txt      # Python dependencies
└── README.md

## MITRE ATT&CK Relevance

| Technique | How LNDG Helps |
|-----------|----------------|
| T1046 - Network Service Discovery | Documents topology WITHOUT active scanning |
| T1018 - Remote System Discovery | Maps devices from existing data sources |
| T1016 - System Network Configuration | Visualizes subnet and VLAN architecture |
| T1590 - Gather Victim Network Info | Provides defensive documentation of network layout |

## Integration with Other Tools

LNDG connects with the LNPS (Linux Network Packet Sniffer) project. Feed LNPS packet captures directly into LNDG to auto-generate network maps from captured traffic.

python run_lndg.py --pcap capture_output.pcap

## Requirements

- Python 3.6+
- matplotlib
- PyYAML

## Author

Larry Odeyemi
- GitHub: github.com/Sh8rlock
- LinkedIn: linkedin.com/in/larryodeyemi

## License

MIT License
