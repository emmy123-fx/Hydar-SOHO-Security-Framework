import nmap

def scan_network(ip_range):
    nm = nmap.PortScanner()
    nm.scan(hosts=ip_range, arguments='-sn')

    active_hosts = []

    for host in nm.all_hosts():
        active_hosts.append({
            "ip": host,
            "status": nm[host].state()
        })

    return active_hosts