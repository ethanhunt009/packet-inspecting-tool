import os
import signal
import threading
import ipaddress
from datetime import datetime
from scapy.all import sniff, IP, TCP, UDP
import dash
from dash import dcc, html, dash_table
from dash.dependencies import Input, Output

# Configuration
interface = 'Wi-Fi'            # Network interface name
RELOAD_INTERVAL = 5            # Config reload check interval
MAX_ENTRIES = 1000             # Max stored connections
DASH_PORT = 8050               # Dashboard port
COLORS = {
    'ip_violation': '#ffcccc',   # Pale red
    'port_violation': '#ffffcc', # Pale yellow
    'both_violation': '#ffd699'  # Orange
}

# Global variables
lock = threading.Lock()
suspicious_connections = []
allowed_networks = []
not_allowed_ports = set()
stop_event = threading.Event()
config_files = {
    'allowed': ('allowed.txt', allowed_networks, 'network'),
    'ports': ('not_allowed_port.txt', not_allowed_ports, 'port')
}
last_modified = {name: 0 for name in config_files}

def read_config(filename, config_type):
    """Read configuration file and return validated entries"""
    items = []
    try:
        with open(filename, 'r') as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith('#'):
                    try:
                        if config_type == 'network':
                            items.append(ipaddress.ip_network(line))
                        elif config_type == 'port':
                            items.append(int(line))
                    except ValueError as e:
                        print(f"Invalid entry '{line}': {str(e)}")
    except FileNotFoundError:
        print(f"Config file {filename} not found")
    return items

def reload_config(filename, store, config_type):
    """Thread-safe configuration reloading"""
    new_items = read_config(filename, config_type)
    
    with lock:
        if config_type == 'network':
            store.clear()
            store.extend(new_items)
            print(f"Reloaded {len(store)} allowed networks")
        elif config_type == 'port':
            store.clear()
            store.update(new_items)
            print(f"Reloaded {len(store)} blocked ports")

def watch_configs():
    """Monitor config files for changes"""
    while not stop_event.is_set():
        try:
            for config_name, (filename, store, type_) in config_files.items():
                if not os.path.exists(filename):
                    continue
                
                mtime = os.path.getmtime(filename)
                if mtime > last_modified[config_name]:
                    print(f"Detected changes in {filename}")
                    reload_config(filename, store, type_)
                    last_modified[config_name] = mtime
        except Exception as e:
            print(f"Config watcher error: {str(e)}")
        
        stop_event.wait(RELOAD_INTERVAL)

def is_ip_allowed(ip):
    """Check if IP is in allowed networks"""
    if not allowed_networks:
        return True  # Allow all if no config
    
    try:
        ip_obj = ipaddress.ip_address(ip)
        return any(ip_obj in network for network in allowed_networks)
    except ValueError:
        return False

def process_packet(packet):
    """Analyze network packets"""
    if IP not in packet:
        return

    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    protocol = src_port = dst_port = None

    if TCP in packet:
        protocol = 'TCP'
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif UDP in packet:
        protocol = 'UDP'
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport

    # Validate connections
    ip_violation = not (is_ip_allowed(src_ip) and is_ip_allowed(dst_ip))
    port_violation = (src_port in not_allowed_ports or 
                     dst_port in not_allowed_ports)

    if ip_violation or port_violation:
        reasons = []
        if ip_violation:
            reasons.append("IP Violation")
        if port_violation:
            reasons.append("Port Violation")

        entry = {
            'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
            'protocol': protocol or 'Other',
            'src_ip': src_ip,
            'dst_ip': dst_ip,
            'src_port': src_port,
            'dst_port': dst_port,
            'reason': ', '.join(reasons)
        }

        with lock:
            suspicious_connections.append(entry)
            if len(suspicious_connections) > MAX_ENTRIES:
                suspicious_connections.pop(0)

def start_sniffing():
    """Start packet capture"""
    try:
        sniff(iface=interface, prn=process_packet, store=0,
             stop_filter=lambda _: stop_event.is_set())
    except Exception as e:
        print(f"Packet capture failed: {str(e)}")
        stop_event.set()

# Dash application setup
app = dash.Dash(__name__)

app.layout = html.Div([
    html.Div([
        html.H1("Network Security Dashboard", 
               style={'textAlign': 'center', 'color': '#ffffff', 'marginBottom': '20px'}),
        
        # Filter Controls
        html.Div([
            dcc.Dropdown(
                id='src-ip-filter',
                placeholder='Select Source IP...',
                multi=True,
                style={'width': '22%', 'margin': '5px'}
            ),
            dcc.Dropdown(
                id='dst-ip-filter',
                placeholder='Select Destination IP...',
                multi=True,
                style={'width': '22%', 'margin': '5px'}
            ),
            dcc.Dropdown(
                id='protocol-filter',
                options=[{'label': 'All Protocols', 'value': 'All'}] + 
                        [{'label': p, 'value': p} for p in ['TCP', 'UDP']],
                value='All',
                clearable=False,
                style={'width': '18%', 'margin': '5px'}
            ),
            dcc.Dropdown(
                id='port-filter',
                placeholder='Select Port...',
                multi=True,
                style={'width': '18%', 'margin': '5px'}
            ),
            dcc.Dropdown(
                id='reason-filter',
                options=[{'label': 'All Reasons', 'value': 'All'}] + 
                        [{'label': r, 'value': r} for r in ['IP Violation', 'Port Violation']],
                value='All',
                clearable=False,
                style={'width': '20%', 'margin': '5px'}
            ),
        ], style={'backgroundColor': '#f8f9fa', 'padding': '10px', 'borderRadius': '5px', 
                'display': 'flex', 'flexWrap': 'wrap'}),

        # Statistics Cards
        html.Div([
            html.Div(id='total-alerts', className='stats-card'),
            html.Div(id='ip-violations', className='stats-card'),
            html.Div(id='port-violations', className='stats-card'),
        ], style={'display': 'flex', 'justifyContent': 'space-between', 'margin': '20px 0'}),

        # Main Data Table
        dcc.Interval(id='refresh', interval=1*1000),
        dash_table.DataTable(
            id='connections-table',
            columns=[
                {'name': 'Timestamp', 'id': 'timestamp'},
                {'name': 'Protocol', 'id': 'protocol'},
                {'name': 'Source IP', 'id': 'src_ip'},
                {'name': 'Destination IP', 'id': 'dst_ip'},
                {'name': 'Source Port', 'id': 'src_port'},
                {'name': 'Dest Port', 'id': 'dst_port'},
                {'name': 'Alert Reason', 'id': 'reason'},
            ],
            style_table={'maxWidth': '1800px', 'margin': '0 auto'},
            style_header={
                'backgroundColor': '#003366',
                'color': 'white',
                'fontWeight': 'bold'
            },
            style_cell={
                'backgroundColor': '#f9f9f9',
                'padding': '10px',
                'textAlign': 'left',
                'border': '1px solid #ddd'
            },
            style_data_conditional=[
                {
                    'if': {'filter_query': '{reason} = "IP Violation"'},
                    'backgroundColor': COLORS['ip_violation'],
                    'color': 'black'
                },
                {
                    'if': {'filter_query': '{reason} = "Port Violation"'},
                    'backgroundColor': COLORS['port_violation'],
                    'color': 'black'
                },
                {
                    'if': {'filter_query': '{reason} = "IP Violation, Port Violation"'},
                    'backgroundColor': COLORS['both_violation'],
                    'color': 'black'
                }
            ],
            page_size=15,
            filter_action='native',
            sort_action='native'
        ),
    ], style={'backgroundColor': '#2c3e50', 'padding': '20px'})
])

@app.callback(
    [Output('src-ip-filter', 'options'),
     Output('dst-ip-filter', 'options'),
     Output('port-filter', 'options')],
    [Input('refresh', 'n_intervals')]
)
def update_filter_options(n):
    with lock:
        df = suspicious_connections[-MAX_ENTRIES:]
    
    src_ips = sorted({entry['src_ip'] for entry in df}, key=lambda ip: ip.split('.'))
    dst_ips = sorted({entry['dst_ip'] for entry in df}, key=lambda ip: ip.split('.'))
    ports = sorted({entry['src_port'] for entry in df} | 
                  {entry['dst_port'] for entry in df} - {None})
    
    return (
        [{'label': ip, 'value': ip} for ip in src_ips],
        [{'label': ip, 'value': ip} for ip in dst_ips],
        [{'label': str(port), 'value': port} for port in ports]
    )

@app.callback(
    [Output('connections-table', 'data'),
     Output('total-alerts', 'children'),
     Output('ip-violations', 'children'),
     Output('port-violations', 'children')],
    [Input('refresh', 'n_intervals'),
     Input('src-ip-filter', 'value'),
     Input('dst-ip-filter', 'value'),
     Input('protocol-filter', 'value'),
     Input('port-filter', 'value'),
     Input('reason-filter', 'value')]
)
def update_dashboard(n, src_ips, dst_ips, protocol, ports, reason):
    with lock:
        df = list(reversed(suspicious_connections[-MAX_ENTRIES:]))
    
    filtered = []
    ip_violations = 0
    port_violations = 0
    
    for entry in df:
        # Source IP filter
        if src_ips and entry['src_ip'] not in (src_ips or []):
            continue
            
        # Destination IP filter
        if dst_ips and entry['dst_ip'] not in (dst_ips or []):
            continue
            
        # Protocol filter
        if protocol != 'All' and entry['protocol'] != protocol:
            continue
            
        # Port filter
        if ports and not (entry['src_port'] in (ports or []) or 
                         entry['dst_port'] in (ports or [])):
            continue
            
        # Reason filter
        if reason != 'All' and reason not in entry['reason']:
            continue
        
        filtered.append(entry)
        
        # Count violations
        if 'IP Violation' in entry['reason']:
            ip_violations += 1
        if 'Port Violation' in entry['reason']:
            port_violations += 1
    
    # Create stats cards
    stats_style = {'fontSize': '24px', 'fontWeight': 'bold', 'marginBottom': '10px'}
    stats = [
        html.Div([
            html.Div(f"Total Alerts: {len(filtered)}", style=stats_style),
            html.Div(f"{len(filtered)} alerts", style={'color': '#666'})
        ]),
        html.Div([
            html.Div(f"IP Violations: {ip_violations}", style=stats_style),
            html.Div(f"{ip_violations} cases", style={'color': '#666'})
        ]),
        html.Div([
            html.Div(f"Port Violations: {port_violations}", style=stats_style),
            html.Div(f"{port_violations} cases", style={'color': '#666'})
        ])
    ]
    
    return filtered, stats[0], stats[1], stats[2]

def signal_handler(sig, frame):
    print("\n[!] Shutting down...")
    stop_event.set()
    exit(0)

if __name__ == '__main__':
    # Initial config load
    for config_name, (filename, store, type_) in config_files.items():
        reload_config(filename, store, type_)

    # Start threads
    threads = [
        threading.Thread(target=start_sniffing, daemon=True),
        threading.Thread(target=watch_configs, daemon=True)
    ]

    for t in threads:
        t.start()

    # Signal handling
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    # Start dashboard
    print(f"[*] Monitoring interface: {interface}")
    print(f"[*] Dashboard: http://localhost:{DASH_PORT}")
    app.run_server(host='127.0.0.1', port=DASH_PORT, debug=False)

    # Cleanup
    stop_event.set()
    for t in threads:
        t.join()