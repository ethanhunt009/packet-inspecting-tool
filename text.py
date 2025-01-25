import os
import time

class ConfigLoader:
    def __init__(self):
        self.suspicious_ports = []
        self.whitelisted_domains = []
        self.ports_file = "suspicious_ports.txt"
        self.domains_file = "whitelisted_domains.txt"
        self.ports_mtime = 0
        self.domains_mtime = 0
        
        # Create default files if missing
        if not os.path.exists(self.ports_file):
            with open(self.ports_file, "w") as f:
                f.write("9050\n9150\n1080\n8080\n8443")
        
        if not os.path.exists(self.domains_file):
            with open(self.domains_file, "w") as f:
                f.write("example.com\ntrusted.org")

    def _load_ports(self):
        try:
            current_mtime = os.path.getmtime(self.ports_file)
            if current_mtime > self.ports_mtime:
                with open(self.ports_file, "r") as f:
                    self.suspicious_ports = [int(line.strip()) for line in f if line.strip().isdigit()]
                self.ports_mtime = current_mtime
        except Exception as e:
            print(f"Error loading ports: {str(e)}")

    def _load_domains(self):
        try:
            current_mtime = os.path.getmtime(self.domains_file)
            if current_mtime > self.domains_mtime:
                with open(self.domains_file, "r") as f:
                    self.whitelisted_domains = [line.strip() for line in f if line.strip()]
                self.domains_mtime = current_mtime
        except Exception as e:
            print(f"Error loading domains: {str(e)}")

    def get_ports(self):
        self._load_ports()
        return self.suspicious_ports

    def get_domains(self):
        self._load_domains()
        return self.whitelisted_domains

# Singleton instance
config = ConfigLoader()