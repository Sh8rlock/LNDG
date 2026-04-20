#!/usr/bin/env python3
"""
LNDG - Linux Network Diagram Generator
Main entry point for generating network topology diagrams.

Usage:
    python run_lndg.py --demo                    # Run with demo enterprise + OT/ICS network
    python run_lndg.py --demo-small              # Run with small office demo
    python run_lndg.py --config network.yaml     # Generate from YAML config
    python run_lndg.py --config network.json     # Generate from JSON config
    python run_lndg.py --nmap scan.xml           # Generate from nmap XML output
    python run_lndg.py --demo --dark             # Dark mode diagrams
    python run_lndg.py --demo --layout purdue    # Use Purdue Model layout
    python run_lndg.py --demo --all-layouts      # Generate all layout variants

Author: Larry Odeyemi
GitHub: github.com/Sh8rlock/LNDG
"""

import argparse
import os
import sys
import time
from datetime import datetime


# ── Banner ───────────────────────────────────────────────────
BANNER = r"""
 ╔══════════════════════════════════════════════════════════╗
 ║     _     _   _ ____   ____                             ║
 ║    | |   | \ | |  _ \ / ___|                            ║
 ║    | |   |  \| | | | | |  _                             ║
 ║    | |___| |\  | |_| | |_| |                            ║
 ║    |_____|_| \_|____/ \____|                             ║
 ║                                                          ║
 ║    Linux Network Diagram Generator v1.0.0                ║
 ║    Network Topology Visualization & Security Analysis    ║
 ║    Author: Larry Odeyemi                                 ║
 ╚══════════════════════════════════════════════════════════╝
"""


def print_banner():
    """Display the LNDG banner."""
    print(BANNER)


def print_stats(topology):
    """Print topology statistics."""
    stats = topology.get_stats()
    print(f"\n{'─' * 56}")
    print(f"  Topology: {topology.name}")
    print(f"  Source:    {topology.metadata.get('source_type', 'unknown')}")
    print(f"{'─' * 56}")
    print(f"  Devices:     {stats['total_devices']}")
    print(f"  Connections: {stats['total_connections']}")
    print(f"  Subnets:     {stats['total_subnets']}")
    print(f"  Zones:       {len(stats['zones'])}")
    print(f"{'─' * 56}")

    print(f"\n  Devices by Zone:")
    for zone, count in sorted(stats['devices_by_zone'].items()):
        bar = '█' * count
        print(f"    {zone:15s} │ {count:3d} │ {bar}")

    print(f"\n  Devices by Type:")
    for dtype, count in sorted(stats['devices_by_type'].items()):
        bar = '▓' * count
        print(f"    {dtype:15s} │ {count:3d} │ {bar}")

    # Risk summary
    risk_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0}
    for device in topology.devices.values():
        risk_counts[device.risk_level] = risk_counts.get(device.risk_level, 0) + 1

    print(f"\n  Risk Distribution:")
    risk_icons = {'critical': '🔴', 'high': '🟠', 'medium': '🟡', 'low': '🟢'}
    for level in ['critical', 'high', 'medium', 'low']:
        count = risk_counts[level]
        icon = risk_icons[level]
        bar = '█' * count
        print(f"    {icon} {level:10s} │ {count:3d} │ {bar}")

    print(f"{'─' * 56}")


def run_demo(args):
    """Run with demo data."""
    from demo_data import generate_demo_topology, generate_small_demo

    print("[*] Generating demo topology...")
    if args.demo_small:
        topology = generate_small_demo()
    else:
        topology = generate_demo_topology()

    print(f"[+] Created {len(topology.devices)} devices, "
          f"{len(topology.connections)} connections, "
          f"{len(topology.subnets)} subnets")

    return topology


def run_config(args):
    """Run with config file input."""
    from config_parser import parse_config

    print(f"[*] Parsing config file: {args.config}")
    topology = parse_config(args.config)
    print(f"[+] Loaded {len(topology.devices)} devices from config")

    return topology


def run_nmap(args):
    """Run with nmap XML input."""
    from nmap_parser import parse_nmap_xml

    print(f"[*] Parsing nmap XML: {args.nmap}")
    topology = parse_nmap_xml(args.nmap)
    print(f"[+] Discovered {len(topology.devices)} hosts from scan")

    return topology


def generate_outputs(topology, args):
    """Generate diagrams and reports."""
    from diagram_engine import generate_diagram, generate_all_diagrams
    from report_generator import generate_html_report, generate_json_report

    output_dir = args.output_dir
    os.makedirs(output_dir, exist_ok=True)

    generated_files = []
    diagram_paths = []

    # Generate diagrams
    print(f"\n[*] Generating diagrams...")
    start_time = time.time()

    if args.all_layouts:
        # Generate all layout variants
        paths = generate_all_diagrams(topology, output_dir=output_dir)
        diagram_paths.extend(paths)
        for p in paths:
            print(f"    [+] {os.path.basename(p)}")
    else:
        # Single layout
        layout = args.layout or 'zone'
        dark = args.dark

        theme = "dark" if dark else "light"
        png_path = os.path.join(output_dir, f"network_{layout}_{theme}.png")
        svg_path = os.path.join(output_dir, f"network_{layout}_{theme}.svg")

        generate_diagram(
            topology,
            output_path=png_path,
            layout=layout,
            dark_mode=dark,
            show_services=args.show_services,
            dpi=args.dpi,
        )
        diagram_paths.append(png_path)
        print(f"    [+] {os.path.basename(png_path)}")

        # Also generate SVG
        generate_diagram(
            topology,
            output_path=svg_path,
            layout=layout,
            dark_mode=dark,
            show_services=args.show_services,
            dpi=args.dpi,
        )
        diagram_paths.append(svg_path)
        print(f"    [+] {os.path.basename(svg_path)}")

    elapsed = time.time() - start_time
    print(f"    Diagrams generated in {elapsed:.2f}s")

    generated_files.extend(diagram_paths)

    # Generate reports
    print(f"\n[*] Generating reports...")

    html_path = os.path.join(output_dir, "lndg_report.html")
    generate_html_report(topology, diagram_paths=diagram_paths, output_path=html_path)
    generated_files.append(html_path)
    print(f"    [+] {os.path.basename(html_path)}")

    json_path = os.path.join(output_dir, "lndg_report.json")
    generate_json_report(topology, output_path=json_path)
    generated_files.append(json_path)
    print(f"    [+] {os.path.basename(json_path)}")

    # Export topology as YAML config (useful for editing and re-running)
    if args.export_config:
        from config_parser import generate_sample_config
        config_path = os.path.join(output_dir, "exported_topology.yaml")
        # Write the topology data as YAML
        import yaml
        export_data = {'network': topology.to_dict()}
        with open(config_path, 'w') as f:
            yaml.dump(export_data, f, default_flow_style=False, sort_keys=False)
        generated_files.append(config_path)
        print(f"    [+] {os.path.basename(config_path)}")

    return generated_files


def main():
    parser = argparse.ArgumentParser(
        description='LNDG - Linux Network Diagram Generator',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python run_lndg.py --demo                     Full enterprise + OT/ICS demo
  python run_lndg.py --demo-small               Small office demo
  python run_lndg.py --demo --dark              Dark mode output
  python run_lndg.py --demo --layout purdue     Purdue Model layout
  python run_lndg.py --demo --all-layouts       All layout variants
  python run_lndg.py --config network.yaml      From YAML config
  python run_lndg.py --nmap scan.xml            From nmap scan results
  python run_lndg.py --demo --export-config     Export topology as YAML
        """
    )

    # Input sources (mutually exclusive)
    input_group = parser.add_mutually_exclusive_group(required=True)
    input_group.add_argument('--demo', action='store_true',
                            help='Run with full enterprise + OT/ICS demo network')
    input_group.add_argument('--demo-small', action='store_true',
                            help='Run with small office demo network')
    input_group.add_argument('--config', type=str,
                            help='Path to YAML or JSON config file')
    input_group.add_argument('--nmap', type=str,
                            help='Path to nmap XML output file')
    input_group.add_argument('--generate-sample', action='store_true',
                            help='Generate sample config and nmap files')

    # Layout options
    parser.add_argument('--layout', type=str, choices=['zone', 'hierarchical', 'purdue'],
                       default='zone', help='Diagram layout algorithm (default: zone)')
    parser.add_argument('--all-layouts', action='store_true',
                       help='Generate all layout variants (light + dark)')
    parser.add_argument('--dark', action='store_true',
                       help='Use dark mode theme')

    # Output options
    parser.add_argument('--output-dir', '-o', type=str, default='output',
                       help='Output directory (default: output)')
    parser.add_argument('--dpi', type=int, default=150,
                       help='Diagram resolution in DPI (default: 150)')
    parser.add_argument('--show-services', action='store_true',
                       help='Show service labels on devices')
    parser.add_argument('--export-config', action='store_true',
                       help='Export topology as YAML config file')

    args = parser.parse_args()

    print_banner()

    # Generate sample files
    if args.generate_sample:
        from config_parser import generate_sample_config
        from nmap_parser import generate_sample_nmap_xml

        print("[*] Generating sample files...")
        yaml_path = generate_sample_config("sample_network.yaml")
        print(f"    [+] {yaml_path}")
        xml_path = generate_sample_nmap_xml("sample_nmap_scan.xml")
        print(f"    [+] {xml_path}")
        print(f"\n[*] Use these as templates:")
        print(f"    python run_lndg.py --config {yaml_path}")
        print(f"    python run_lndg.py --nmap {xml_path}")
        return

    # Load topology from selected source
    if args.demo or args.demo_small:
        topology = run_demo(args)
    elif args.config:
        topology = run_config(args)
    elif args.nmap:
        topology = run_nmap(args)

    # Print stats
    print_stats(topology)

    # Generate outputs
    generated = generate_outputs(topology, args)

    # Summary
    print(f"\n{'═' * 56}")
    print(f"  LNDG COMPLETE")
    print(f"{'═' * 56}")
    print(f"  Output directory: {os.path.abspath(args.output_dir)}")
    print(f"  Files generated:  {len(generated)}")
    for f in generated:
        size = os.path.getsize(f)
        size_str = f"{size / 1024:.1f} KB" if size > 1024 else f"{size} B"
        print(f"    • {os.path.basename(f):40s} {size_str}")
    print(f"{'═' * 56}")
    print(f"  Open lndg_report.html in a browser to view the full report.")
    print()


if __name__ == '__main__':
    main()

