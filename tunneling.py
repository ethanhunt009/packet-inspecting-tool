import requests
import threading
from scapy.all import sniff, IP, DNS, DNSQR, TCP
from scapy.layers.http import HTTP, HTTPRequest
import warnings
from urllib3.exceptions import InsecureRequestWarning
from text import config
from dashb import add_threat, run_dashboard

# Suppress warnings
warnings.filterwarnings("ignore", category=UserWarning)
warnings.filterwarnings("ignore", category=InsecureRequestWarning)

# Configuration
TOR_EXIT_NODES_URL = "https://check.torproject.org/torbulkexitlist"
NETWORK_INTERFACE = "Wi-Fi"

class NetworkStealthDetector:
    def __init__(self):
        self.tor_exit_nodes = self._fetch_tor_exit_nodes()
        self.user_agents = {}
        self.dns_history = {}

    def _fetch_tor_exit_nodes(self):
        try:
            response = requests.get(TOR_EXIT_NODES_URL, verify=False, timeout=10)
            return set(response.text.strip().split('\n'))
        except Exception as e:
            add_threat({
                'threat_type': 'System Error',
                'source': 'Monitoring',
                'details': f"Tor node fetch failed: {str(e)}"
            })
            return set()

    def _detect_tor_traffic(self, packet):
        if IP in packet and TCP in packet:
            if packet[IP].dst in self.tor_exit_nodes:
                add_threat({
                    'threat_type': 'TOR Traffic',
                    'source_ip': packet[IP].src,
                    'destination_ip': packet[IP].dst,
                    'details': f"Connected to Tor exit node {packet[IP].dst}"
                })

    def _detect_proxy_chains(self, packet):
        if IP in packet and TCP in packet:
            current_ports = config.get_ports()
            if packet[TCP].dport in current_ports:
                add_threat({
                    'threat_type': 'Proxy Chain',
                    'source_ip': packet[IP].src,
                    'destination_port': packet[TCP].dport,
                    'details': f"Suspicious port {packet[TCP].dport}"
                })
            
            if HTTPRequest in packet:
                src_ip = packet[IP].src
                user_agent = packet[HTTPRequest].User_Agent.decode() if packet[HTTPRequest].User_Agent else ""
                
                if user_agent:
                    if src_ip in self.user_agents:
                        if user_agent not in self.user_agents[src_ip]:
                            add_threat({
                                'threat_type': 'Proxy Chain',
                                'source_ip': src_ip,
                                'details': f"Multiple User-Agents detected: {user_agent}"
                            })
                            self.user_agents[src_ip].add(user_agent)
                    else:
                        self.user_agents[src_ip] = {user_agent}

    def _detect_domain_fronting(self, packet):
        if IP in packet and HTTP in packet:
            try:
                http_layer = packet[HTTP]
                if 'Host' in http_layer.fields:
                    host = http_layer.Host.decode()
                    src_ip = packet[IP].src
                    current_domains = config.get_domains()
                    
                    if src_ip in self.dns_history:
                        if host != self.dns_history[src_ip] and self.dns_history[src_ip] in current_domains:
                            add_threat({
                                'threat_type': 'Domain Fronting',
                                'source_ip': src_ip,
                                'details': f"SNI: {self.dns_history[src_ip]} | Host: {host}"
                            })
            except:
                pass

    def _detect_dns_tunneling(self, packet):
        if IP in packet and DNS in packet and packet[DNS].qr == 0:
            query = packet[DNSQR].qname.decode()
            src_ip = packet[IP].src
            self.dns_history[src_ip] = query.split('.')[-2]
            
            suspicious = any([
                len(query) > 50,
                query.count('.') > 5,
                any(c.isdigit() for c in query),
                '_' in query,
                'txt' in query.lower()
            ])
            
            if suspicious:
                add_threat({
                    'threat_type': 'DNS Tunneling',
                    'source_ip': src_ip,
                    'details': f"Suspicious query: {query}"
                })

    def analyze_packet(self, packet):
        if IP not in packet:
            return
            
        self._detect_tor_traffic(packet)
        self._detect_proxy_chains(packet)
        self._detect_domain_fronting(packet)
        self._detect_dns_tunneling(packet)

def main():
    # Start dashboard in separate thread
    dashboard_thread = threading.Thread(target=run_dashboard, daemon=True)
    dashboard_thread.start()
    
    detector = NetworkStealthDetector()
    print(f"🚀 Starting network monitoring on {NETWORK_INTERFACE}")
    print(f"🌐 Dashboard available at http://localhost:8051")
    print(f"🔍 Auto-reloading config from:")
    print(f" - suspicious_ports.txt")
    print(f" - whitelisted_domains.txt\n")
    
    sniff(
        prn=detector.analyze_packet,
        store=0,
        filter="tcp or udp",
        iface=NETWORK_INTERFACE
    )

if __name__ == "__main__":
    main()