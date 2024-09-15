import re
import logging
import json
import xml.etree.ElementTree as ET
from pathlib import Path

def is_valid_ip(ip):
    """
    Validate an IPv4 address.
    """
    pattern = re.compile(
        r"^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$"
    )
    if pattern.match(ip):
        parts = ip.split(".")
        if all(0 <= int(part) <= 255 for part in parts):
            return True
    return False

def parse_port_range(port_range):
    """
    Parse port range string and return a list of ports.
    """
    try:
        start, end = map(int, port_range.split('-'))
        if start > end or start < 1 or end > 65535:
            raise ValueError
        return list(range(start, end + 1))
    except Exception:
        raise ValueError("Invalid port range format. Use start-end (e.g., 1-1024)")

def setup_logger(log_file='scanner.log'):
    """
    Set up logging for the application.
    """
    logger = logging.getLogger('AdvancedNetworkScanner')
    logger.setLevel(logging.DEBUG)

    # Create handlers
    fh = logging.FileHandler(log_file)
    fh.setLevel(logging.DEBUG)
    ch = logging.StreamHandler()
    ch.setLevel(logging.INFO)

    # Create formatter and add to handlers
    formatter = logging.Formatter('%(asctime)s - %(levelname)s - %(message)s')
    fh.setFormatter(formatter)
    ch.setFormatter(formatter)

    # Add handlers to logger
    logger.addHandler(fh)
    logger.addHandler(ch)

    return logger

def save_to_json(data, filename):
    """
    Save data to a JSON file.
    """
    with open(filename, 'w') as f:
        json.dump(data, f, indent=4)

def save_to_csv(data, filename):
    """
    Save data to a CSV file.
    """
    import csv
    with open(filename, 'w', newline='') as f:
        writer = csv.writer(f)
        if isinstance(data, list) and len(data) > 0 and isinstance(data[0], dict):
            headers = data[0].keys()
            writer.writerow(headers)
            for entry in data:
                writer.writerow(entry.values())
        else:
            writer.writerow(['Data'])
            writer.writerows([[d] for d in data])

def save_to_xml(data, filename):
    """
    Save data to an XML file.
    """
    root = ET.Element("scan_results")
    for entry in data:
        port_element = ET.SubElement(root, "port")
        for key, value in entry.items():
            child = ET.SubElement(port_element, key)
            child.text = str(value)
    tree = ET.ElementTree(root)
    tree.write(filename, encoding='utf-8', xml_declaration=True)

def load_config(config_path):
    """
    Load configuration from a JSON file.
    """
    if Path(config_path).is_file():
        with open(config_path, 'r') as f:
            return json.load(f)
    else:
        raise FileNotFoundError(f"Configuration file {config_path} not found.")
