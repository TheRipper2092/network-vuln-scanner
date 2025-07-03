import nmap

def scan_target(target):
    nm = nmap.PortScanner()
    try:
        nm.scan(hosts=target, arguments='-O -sV')
        result = nm[target]

        open_ports = []
        for proto in result.all_protocols():
            ports = result[proto].keys()
            for port in ports:
                service = result[proto][port].get('name', 'unknown')
                open_ports.append({
                    'port': port,
                    'protocol': proto,
                    'service': service
                })

        os_guess = result.get('osmatch', [{}])[0].get('name', 'Unknown')

        return {
            'status': 'success',
            'hostname': result.hostname(),
            'open_ports': open_ports,
            'os': os_guess
        }

    except Exception as e:
        return {
            'status': 'error',
            'message': str(e)
        }
