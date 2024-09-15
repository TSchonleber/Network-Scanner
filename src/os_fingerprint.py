# os_fingerprint.py

from scapy.all import IP, TCP, sr1
from utils import setup_logger

logger = setup_logger()

def os_fingerprint(target, timeout=2):
    """
    Determine the operating system of the target host based on TTL values.
    """
    try:
        pkt = IP(dst=target)/TCP(dport=80, flags='S')
        response = sr1(pkt, timeout=timeout, verbose=0)
        if response:
            ttl = response.ttl
            logger.debug(f"Received TTL: {ttl} from {target}")
            if ttl <= 64:
                return "Linux/Unix"
            elif ttl <= 128:
                return "Windows"
            else:
                return "Unknown"
        else:
            logger.warning(f"No response received from {target} for OS fingerprinting.")
            return "No response"
    except Exception as e:
        logger.error(f"Error during OS fingerprinting: {e}")
        return "Error"

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="OS Fingerprinting Tool")
    parser.add_argument('--target', required=True, help='Target IP address')
    args = parser.parse_args()

    target = args.target
    os = os_fingerprint(target)
    print(f"Detected OS for {target}: {os}")
