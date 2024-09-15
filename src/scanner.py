# scanner.py (Further Updated)

import socket
import concurrent.futures
import json
from core import banner_grab
from os_fingerprint import os_fingerprint
from vulnerability_checker import get_cves, format_cve
from utils import is_valid_ip, parse_port_range, setup_logger, load_config
# Example usage in scanner.py

config = load_config('config.json')
scanner = PortScanner(
    target=config['target'],
    ports=parse_port_range(config['ports']),
    timeout=1
)
# Proceed with scanning...

logger = setup_logger()

class PortScanner:
    def __init__(self, target: str, ports: list, timeout: int = 1):
        if not is_valid_ip(target):
            logger.error(f"Invalid IP address: {target}")
            raise ValueError("Invalid IP address.")
        self.target = target
        self.ports = ports
        self.timeout = timeout
        self.open_ports = []
        self.os = None
        self.vulnerabilities = []

    def scan_port(self, port: int):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
                sock.settimeout(self.timeout)
                result = sock.connect_ex((self.target, port))
                if result == 0:
                    banner = banner_grab(self.target, port)
                    logger.info(f"Port {port} is open: {banner}")
                    self.open_ports.append({'port': port, 'service': banner})
        except socket.timeout:
            logger.debug(f"Timeout reached on port {port}")
        except socket.error as e:
            logger.error(f"Socket error on port {port}: {e}")
        except Exception as e:
            logger.exception(f"Unexpected error on port {port}: {e}")

    def run_scan(self):
        with concurrent.futures.ThreadPoolExecutor(max_workers=100) as executor:
            executor.map(self.scan_port, self.ports)
        return self.open_ports

    def perform_os_fingerprinting(self):
        self.os = os_fingerprint(self.target)
        logger.info(f"Detected OS: {self.os}")
        return self.os

    def check_vulnerabilities(self):
        for port_info in self.open_ports:
            service_info = port_info['service']
            if service_info != "Unknown":
                # Extract service name and version
                parts = service_info.split()
                service = parts[0]
                version = ' '.join(parts[1:]) if len(parts) > 1 else 'N/A'
                if version != 'N/A':
                    cves = get_cves(service, version)
                    formatted = [format_cve(cve) for cve in cves]
                    self.vulnerabilities.append({
                        'port': port_info['port'],
                        'service': service,
                        'version': version,
                        'cves': formatted
                    })
        logger.info(f"Total vulnerabilities found: {len(self.vulnerabilities)}")
        return self.vulnerabilities

    def save_results(self, filename, format='json'):
        if format == 'json':
            from utils import save_to_json
            data = {
                'target': self.target,
                'os': self.os,
                'open_ports': self.open_ports,
                'vulnerabilities': self.vulnerabilities
            }
            save_to_json(data, filename)
        elif format == 'csv':
            from utils import save_to_csv
            # For CSV, flatten the vulnerabilities
            flattened = []
            for vuln in self.vulnerabilities:
                for cve in vuln['cves']:
                    flattened.append({
                        'target': self.target,
                        'os': self.os,
                        'port': vuln['port'],
                        'service': vuln['service'],
                        'version': vuln['version'],
                        'cve_id': cve['id'],
                        'cve_summary': cve['summary'],
                        'cvss_score': cve['cvss_score'],
                        'published_date': cve['published_date']
                    })
            save_to_csv(flattened, filename)
        elif format == 'xml':
            from utils import save_to_xml
            data = {
                'target': self.target,
                'os': self.os,
                'open_ports': self.open_ports,
                'vulnerabilities': self.vulnerabilities
            }
            save_to_xml(data, filename)
        else:
            logger.warning("Unsupported format. Defaulting to JSON.")
            from utils import save_to_json
            data = {
                'target': self.target,
                'os': self.os,
                'open_ports': self.open_ports,
                'vulnerabilities': self.vulnerabilities
            }
            save_to_json(data, filename)

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Advanced Network Scanner")
    parser.add_argument('--target', required=True, help='Target IP address')
    parser.add_argument('--ports', default='1-1024', help='Port range (e.g., 1-1024)')
    parser.add_argument('--output', default='scan_results.json', help='Output file name')
    parser.add_argument('--format', default='json', choices=['json', 'csv', 'xml'], help='Output format')

    args = parser.parse_args()

    try:
        target = args.target
        port_range = args.ports
        output_file = args.output
        output_format = args.format

        if not is_valid_ip(target):
            logger.error(f"Invalid IP address: {target}")
            exit(1)

        ports = parse_port_range(port_range)
        scanner = PortScanner(target, ports)
        open_ports = scanner.run_scan()
        scanner.perform_os_fingerprinting()
        vulnerabilities = scanner.check_vulnerabilities()
        scanner.save_results(output_file, format=output_format)
        logger.info(f"Scan completed. Results saved to {output_file}")
    except Exception as e:
        logger.exception(f"An unexpected error occurred: {e}")
        exit(1)
