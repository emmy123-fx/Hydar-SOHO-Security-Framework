from modules.scanner import scan_network

results = scan_network("192.168.1.0/24")

for device in results:
    print(device)