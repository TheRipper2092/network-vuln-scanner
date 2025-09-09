# scanner.py
import nmap
import subprocess
import re
import os
import shutil

def get_all_nmap_scripts():
    """
    Dynamically finds the Nmap executable and fetches a list of all available NSE scripts.
    This is more robust than a hardcoded path.
    """
    nmap_path = shutil.which('nmap')
    if not nmap_path:
        print("Error: Nmap executable not found in PATH.")
        return []
        
    try:
        # Uses subprocess to get a list of all scripts from Nmap's help output
        output = subprocess.check_output([nmap_path, '--script-help'], text=True)
        scripts = re.findall(r'^Script name: (\S+)', output, flags=re.MULTILINE)
        return sorted(set(scripts))
    except Exception as e:
        print(f'Error fetching nmap scripts: {e}')
        return []

def scan_target(target, options, scripts):
    """
    Performs the Nmap scan using the python-nmap library and returns a structured result.
    
    This function has been updated to:
    1. Catch specific exceptions for better error handling.
    2. Ensure a default 'message' is always available in the error case.
    """
    nm = nmap.PortScanner()
    try:
        args = ' '.join(options)
        if scripts:
            args += ' --script=' + ','.join(scripts)
            
        # Execute the scan with the python-nmap library
        nm.scan(hosts=target, arguments=args)
        
        # Check if the target is up and the scan succeeded
        if target not in nm.all_hosts():
            return {
                'status': 'error',
                'message': f"Scan failed for target {target}. It may be down or unreachable."
            }

        scan_result = nm[target]

        ports_info = []
        for proto in scan_result.all_protocols():
            ports = scan_result[proto].keys()
            for port in sorted(ports):
                port_data = scan_result[proto][port]
                ports_info.append({
                    'port': port,
                    'protocol': proto,
                    'state': port_data.get('state', 'unknown'),
                    'service': port_data.get('name', 'unknown'),
                    'product': port_data.get('product', ''),
                    'version': port_data.get('version', ''),
                    'extra_info': port_data.get('extrainfo', ''),
                    'script_results': port_data.get('script', {})
                })

        # Get OS guess from scan results
        os_guess = scan_result.get('osmatch', [{}])[0].get('name', 'Unknown') if scan_result.get('osmatch') else "Unknown"

        return {
            'status': 'success',
            'hostname': scan_result.hostname(),
            'ports': ports_info,
            'os': os_guess
        }
    except nmap.PortScannerError as e:
        # Catch a specific error if Nmap fails to run
        return {
            'status': 'error',
            'message': f"Nmap scanning error: {str(e)}. Please check your Nmap installation."
        }
    except Exception as e:
        # Catch any other unexpected errors
        return {
            'status': 'error',
            'message': f"An unexpected error occurred during the scan: {str(e)}"
        }
