"""
LNDG - Diagram Engine
Generates professional network topology diagrams using matplotlib.
Supports security zone coloring, device type icons, and multiple layouts.
"""

import math
import os
from datetime import datetime

import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch

from network_model import ZONE_CONFIG, DEVICE_MARKERS, NetworkTopology


# Layout algorithms
def _layout_zone_grouped(topology):
    """Layout devices grouped by security zone in horizontal bands."""
    positions = {}
    zones = sorted(
        set(d.zone for d in topology.devices.values()),
        key=lambda z: ZONE_CONFIG.get(z, {}).get('trust', 3)
    )

    zone_y_start = 0.95
    zone_height = 0.85 / max(len(zones), 1)

    for zone_idx, zone in enumerate(zones):
        zone_devices = [name for name, d in topology.devices.items() if d.zone == zone]
        if not zone_devices:
            continue

        y_center = zone_y_start - (zone_idx * zone_height) - (zone_height / 2)
        num_devices = len(zone_devices)

        # Spread devices horizontally
        x_margin = 0.08
        x_range = 1.0 - (2 * x_margin)

        for i, device_name in enumerate(zone_devices):
            if num_devices == 1:
                x = 0.5
            else:
                x = x_margin + (i * x_range / (num_devices - 1))
            positions[device_name] = (x, y_center)

    return positions


def _layout_hierarchical(topology):
    """Layout devices in hierarchical tiers based on device type."""
    tier_order = {
        'cloud': 0, 'internet': 0,
        'firewall': 1, 'router': 1,
        'ids': 2,
        'switch': 2,
        'server': 3, 'database': 3, 'historian': 3,
        'scada': 4,
        'hmi': 5, 'engineering': 5,
        'workstation': 6, 'printer': 6,
        'plc': 7,
        'iot': 8,
        'generic': 6,
    }

    tiers = {}
    for name, device in topology.devices.items():
        tier = tier_order.get(device.device_type, 6)
        if tier not in tiers:
            tiers[tier] = []
        tiers[tier].append(name)

    positions = {}
    sorted_tiers = sorted(tiers.keys())
    num_tiers = len(sorted_tiers)

    for tier_idx, tier in enumerate(sorted_tiers):
        devices = tiers[tier]
        y = 0.92 - (tier_idx * 0.82 / max(num_tiers - 1, 1))

        x_margin = 0.06
        x_range = 1.0 - (2 * x_margin)

        for i, device_name in enumerate(devices):
            if len(devices) == 1:
                x = 0.5
            else:
                x = x_margin + (i * x_range / (len(devices) - 1))
            positions[device_name] = (x, y)

    return positions


def _layout_purdue(topology):
    """Layout OT/ICS devices using the Purdue Model levels."""
    purdue_levels = {
        'internet': {'level': 5, 'label': 'Level 5 - Enterprise'},
        'dmz': {'level': 4, 'label': 'Level 4 - DMZ'},
        'corporate': {'level': 3.5, 'label': 'Level 3.5 - IT/OT DMZ'},
        'management': {'level': 3.5, 'label': 'Level 3.5 - Management'},
        'cloud': {'level': 5, 'label': 'Level 5 - Cloud'},
    }

    # Assign OT devices to Purdue levels based on subnet
    subnet_levels = {}
    for name, subnet in topology.subnets.items():
        if 'Level0' in name or 'level0' in name:
            subnet_levels[name] = 0
        elif 'Level1' in name or 'level1' in name:
            subnet_levels[name] = 1
        elif 'Level2' in name or 'level2' in name:
            subnet_levels[name] = 2
        elif 'Level3' in name or 'level3' in name:
            subnet_levels[name] = 3

    levels = {}
    for name, device in topology.devices.items():
        if device.subnet and device.subnet in subnet_levels:
            level = subnet_levels[device.subnet]
        elif device.zone in purdue_levels:
            level = purdue_levels[device.zone]['level']
        else:
            level = 3.5
        level_key = level
        if level_key not in levels:
            levels[level_key] = []
        levels[level_key].append(name)

    positions = {}
    sorted_levels = sorted(levels.keys(), reverse=True)
    num_levels = len(sorted_levels)

    for level_idx, level in enumerate(sorted_levels):
        devices = levels[level]
        y = 0.92 - (level_idx * 0.82 / max(num_levels - 1, 1))

        x_margin = 0.06
        x_range = 1.0 - (2 * x_margin)

        for i, device_name in enumerate(devices):
            if len(devices) == 1:
                x = 0.5
            else:
                x = x_margin + (i * x_range / (len(devices) - 1))
            positions[device_name] = (x, y)

    return positions


LAYOUTS = {
    'zone': _layout_zone_grouped,
    'hierarchical': _layout_hierarchical,
    'purdue': _layout_purdue,
}


def generate_diagram(topology, output_path="network_diagram.png",
                     layout="zone", title=None, figsize=None,
                     show_legend=True, show_labels=True,
                     show_connections=True, show_services=False,
                     dark_mode=False, dpi=150):
    """
    Generate a network topology diagram.

    Args:
        topology: NetworkTopology object
        output_path: Output file path (.png or .svg)
        layout: Layout algorithm ('zone', 'hierarchical', 'purdue')
        title: Diagram title (defaults to topology name)
        figsize: Figure size tuple (width, height)
        show_legend: Show device type and zone legend
        show_labels: Show device name labels
        show_connections: Draw connection lines
        show_services: Show service labels on devices
        dark_mode: Use dark background theme
        dpi: Output resolution
    """
    num_devices = len(topology.devices)
    if figsize is None:
        width = max(16, min(28, num_devices * 1.2))
        height = max(10, min(20, num_devices * 0.7))
        figsize = (width, height)

    # Theme
    if dark_mode:
        bg_color = '#1a1a2e'
        text_color = '#e0e0e0'
        edge_color = '#4a4a6a'
        grid_color = '#2a2a4a'
        title_color = '#ffffff'
    else:
        bg_color = '#fafafa'
        text_color = '#333333'
        edge_color = '#cccccc'
        grid_color = '#eeeeee'
        title_color = '#1a1a1a'

    fig, ax = plt.subplots(1, 1, figsize=figsize)
    fig.patch.set_facecolor(bg_color)
    ax.set_facecolor(bg_color)

    # Get layout positions
    layout_fn = LAYOUTS.get(layout, _layout_zone_grouped)
    positions = layout_fn(topology)

    # Draw zone backgrounds
    _draw_zone_backgrounds(ax, topology, positions, dark_mode)

    # Draw connections
    if show_connections:
        _draw_connections(ax, topology, positions, dark_mode)

    # Draw devices
    _draw_devices(ax, topology, positions, show_labels, show_services,
                  dark_mode, text_color)

    # Title
    diagram_title = title or topology.name
    ax.set_title(diagram_title, fontsize=18, fontweight='bold',
                 color=title_color, pad=20)

    # Legend
    if show_legend:
        _draw_legend(ax, topology, dark_mode, text_color)

    # Stats annotation
    stats = topology.get_stats()
    stats_text = (f"Devices: {stats['total_devices']}  |  "
                  f"Connections: {stats['total_connections']}  |  "
                  f"Subnets: {stats['total_subnets']}  |  "
                  f"Zones: {len(stats['zones'])}")
    ax.annotate(stats_text, xy=(0.5, -0.02), xycoords='axes fraction',
                ha='center', fontsize=9, color=text_color, alpha=0.7)

    # Timestamp
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    ax.annotate(f"Generated by LNDG v1.0 | {timestamp}",
                xy=(0.99, -0.04), xycoords='axes fraction',
                ha='right', fontsize=7, color=text_color, alpha=0.5)

    ax.set_xlim(-0.05, 1.05)
    ax.set_ylim(-0.08, 1.05)
    ax.axis('off')

    plt.tight_layout()
    plt.savefig(output_path, dpi=dpi, bbox_inches='tight',
                facecolor=fig.get_facecolor(), edgecolor='none')
    plt.close(fig)

    return output_path


def _draw_zone_backgrounds(ax, topology, positions, dark_mode):
    """Draw colored background bands for each security zone."""
    zone_devices = {}
    for name, device in topology.devices.items():
        if name in positions:
            if device.zone not in zone_devices:
                zone_devices[device.zone] = []
            zone_devices[device.zone].append(positions[name])

    for zone, device_positions in zone_devices.items():
        if not device_positions:
            continue

        config = ZONE_CONFIG.get(zone, ZONE_CONFIG['internal'])
        ys = [p[1] for p in device_positions]
        y_min = min(ys) - 0.04
        y_max = max(ys) + 0.04

        alpha = 0.15 if dark_mode else 0.25
        rect = FancyBboxPatch(
            (-0.03, y_min), 1.06, y_max - y_min,
            boxstyle="round,pad=0.01",
            facecolor=config['bg'] if not dark_mode else config['color'],
            alpha=alpha,
            edgecolor=config['color'],
            linewidth=1.5,
            linestyle='--'
        )
        ax.add_patch(rect)

        # Zone label
        label_color = config['color']
        ax.text(-0.01, (y_min + y_max) / 2, config['label'],
                fontsize=8, fontweight='bold', color=label_color,
                ha='right', va='center', rotation=90, alpha=0.8)


def _draw_connections(ax, topology, positions, dark_mode):
    """Draw connection lines between devices."""
    for conn in topology.connections:
        if conn.source not in positions or conn.target not in positions:
            continue

        src_pos = positions[conn.source]
        tgt_pos = positions[conn.target]

        # Style based on encryption
        if conn.encrypted:
            linestyle = '-'
            linewidth = 1.5
            color = '#059669' if not dark_mode else '#34d399'
        else:
            linestyle = '--'
            linewidth = 1.0
            color = '#9ca3af' if not dark_mode else '#6b7280'

        # OT connections in amber
        src_device = topology.devices.get(conn.source)
        tgt_device = topology.devices.get(conn.target)
        if src_device and tgt_device:
            if src_device.zone == 'ot' and tgt_device.zone == 'ot':
                color = '#d97706' if not dark_mode else '#fbbf24'

        ax.plot([src_pos[0], tgt_pos[0]], [src_pos[1], tgt_pos[1]],
                color=color, linewidth=linewidth, linestyle=linestyle,
                alpha=0.5, zorder=1)

        # Connection label at midpoint
        if conn.label:
            mid_x = (src_pos[0] + tgt_pos[0]) / 2
            mid_y = (src_pos[1] + tgt_pos[1]) / 2
            ax.text(mid_x, mid_y, conn.label, fontsize=5,
                    ha='center', va='center', color=color, alpha=0.6,
                    bbox=dict(boxstyle='round,pad=0.1',
                              facecolor='white' if not dark_mode else '#1a1a2e',
                              alpha=0.7, edgecolor='none'))


def _draw_devices(ax, topology, positions, show_labels, show_services,
                  dark_mode, text_color):
    """Draw device nodes with type-specific markers."""
    for name, device in topology.devices.items():
        if name not in positions:
            continue

        pos = positions[name]
        config = ZONE_CONFIG.get(device.zone, ZONE_CONFIG['internal'])
        marker_config = DEVICE_MARKERS.get(device.device_type, DEVICE_MARKERS['generic'])

        # Risk-based border
        risk_colors = {
            'critical': '#DC2626',
            'high': '#EA580C',
            'medium': '#F59E0B',
            'low': config['color'],
        }
        edge_color = risk_colors.get(device.risk_level, config['color'])

        ax.scatter(pos[0], pos[1],
                   marker=marker_config['marker'],
                   s=marker_config['size'],
                   c=config['color'] if not dark_mode else config['bg'],
                   edgecolors=edge_color,
                   linewidths=2.5 if device.risk_level in ('critical', 'high') else 1.5,
                   zorder=3,
                   alpha=0.9)

        if show_labels:
            # Device type icon above
            ax.text(pos[0], pos[1] + 0.025, marker_config['icon'],
                    fontsize=6, ha='center', va='bottom',
                    fontweight='bold', color=config['color'], alpha=0.8)

            # Device name below
            label = name
            if device.ip:
                label += f"\n{device.ip}"
            ax.text(pos[0], pos[1] - 0.025, label,
                    fontsize=6.5, ha='center', va='top',
                    color=text_color, fontweight='bold',
                    bbox=dict(boxstyle='round,pad=0.15',
                              facecolor='white' if not dark_mode else '#2a2a4a',
                              alpha=0.8, edgecolor='none'))

        if show_services and device.services:
            svc_text = ', '.join(device.services[:3])
            if len(device.services) > 3:
                svc_text += f' +{len(device.services) - 3}'
            ax.text(pos[0], pos[1] - 0.055, svc_text,
                    fontsize=5, ha='center', va='top',
                    color=text_color, alpha=0.6,
                    style='italic')


def _draw_legend(ax, topology, dark_mode, text_color):
    """Draw device type and zone legend."""
    # Zone legend
    zone_patches = []
    used_zones = set(d.zone for d in topology.devices.values())
    for zone in sorted(used_zones):
        config = ZONE_CONFIG.get(zone, ZONE_CONFIG['internal'])
        patch = mpatches.Patch(
            facecolor=config['bg'] if not dark_mode else config['color'],
            edgecolor=config['color'],
            label=config['label'],
            alpha=0.6
        )
        zone_patches.append(patch)

    if zone_patches:
        zone_legend = ax.legend(
            handles=zone_patches,
            loc='upper right',
            title='Security Zones',
            fontsize=7,
            title_fontsize=8,
            framealpha=0.9,
            facecolor='white' if not dark_mode else '#2a2a4a',
            edgecolor=text_color,
            labelcolor=text_color,
        )
        zone_legend.get_title().set_color(text_color)
        ax.add_artist(zone_legend)

    # Device type legend
    type_patches = []
    used_types = set(d.device_type for d in topology.devices.values())
    for dtype in sorted(used_types):
        marker_config = DEVICE_MARKERS.get(dtype, DEVICE_MARKERS['generic'])
        type_patches.append(
            plt.Line2D([0], [0],
                       marker=marker_config['marker'],
                       color='w',
                       markerfacecolor='#6b7280',
                       markeredgecolor='#374151',
                       markersize=8,
                       label=f"{marker_config['icon']} {dtype.capitalize()}")
        )

    if type_patches:
        type_legend = ax.legend(
            handles=type_patches,
            loc='lower right',
            title='Device Types',
            fontsize=6,
            title_fontsize=7,
            framealpha=0.9,
            facecolor='white' if not dark_mode else '#2a2a4a',
            edgecolor=text_color,
            labelcolor=text_color,
            ncol=2,
        )
        type_legend.get_title().set_color(text_color)
        ax.add_artist(type_legend)


def generate_all_diagrams(topology, output_dir="diagrams"):
    """Generate diagrams in all available layouts and themes."""
    os.makedirs(output_dir, exist_ok=True)
    generated = []

    for layout_name in LAYOUTS:
        for dark in [False, True]:
            theme = "dark" if dark else "light"
            filename = f"network_{layout_name}_{theme}.png"
            filepath = os.path.join(output_dir, filename)

            generate_diagram(
                topology,
                output_path=filepath,
                layout=layout_name,
                dark_mode=dark,
                show_services=(layout_name == 'purdue'),
                title=f"{topology.name} ({layout_name.capitalize()} Layout)",
                dpi=150
            )
            generated.append(filepath)

    # Also generate SVG version of the zone layout
    svg_path = os.path.join(output_dir, "network_zone_light.svg")
    generate_diagram(
        topology,
        output_path=svg_path,
        layout='zone',
        dark_mode=False,
        dpi=150
    )
    generated.append(svg_path)

    return generated

