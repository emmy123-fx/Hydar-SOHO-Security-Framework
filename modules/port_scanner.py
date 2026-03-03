"""Port scanning helpers using nmap."""

import nmap


def scan_ports(target: str):
    """Perform a TCP SYN port scan with service/version detection.

    Args:
        target: IP range or hostname to scan (e.g. "192.168.1.1/24").

    Returns:
        A list of dictionaries for each open port:

            [
                {
                    "port": 22,
                    "protocol": "tcp",
                    "service": "ssh",
                    "version": "OpenSSH 8.4p1"
                },
                ...
            ]
    """

    nm = nmap.PortScanner()
    # -sS  TCP SYN scan
    # -sV  service/version detection
    # --open only show open ports (python-nmap handles filtering later)
    nm.scan(hosts=target, arguments='-sS -sV')

    port_list = []
    for host in nm.all_hosts():
        # each host may have multiple protocols (tcp/udp)
        for proto in nm[host].all_protocols():
            ports = nm[host][proto].keys()
            for port in sorted(ports):
                info = nm[host][proto][port]
                if info.get('state') != 'open':
                    continue
                port_list.append({
                    "host": host,
                    "port": port,
                    "protocol": proto,
                    "service": info.get('name'),
                    "version": info.get('version'),
                })

    return port_list
