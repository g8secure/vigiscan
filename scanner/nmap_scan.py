import nmap

def run_nmap_scan(target):
    scanner = nmap.PortScanner()
    scanner.scan(target, arguments='-sV')

    results = {}

    for host in scanner.all_hosts():
        results[host] = []
        for proto in scanner[host].all_protocols():
            ports = scanner[host][proto].keys()
            for port in ports:
                results[host].append({
                    "port": port,
                    "service": scanner[host][proto][port]['name']
                })

    return results