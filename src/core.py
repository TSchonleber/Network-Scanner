# core.py

import socket
from utils import setup_logger

logger = setup_logger()

def banner_grab(ip, port):
    """
    Retrieve the service banner from an open port.
    """
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(2)
        sock.connect((ip, port))
        banner = sock.recv(1024).decode().strip()
        sock.close()
        logger.debug(f"Banner grabbed from {ip}:{port} - {banner}")
        return banner
    except Exception as e:
        logger.debug(f"Failed to grab banner from {ip}:{port} - {e}")
        return "Unknown"
