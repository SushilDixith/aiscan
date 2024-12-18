import nmap

def run_scan(target_ip, scan_args=""):
    nm = nmap.PortScanner()
    try:
        print(f"Running scan on {target_ip} with args '{scan_args}'")
        nm.scan(hosts=target_ip, arguments=scan_args)
        return nm.all_hosts()
    except Exception as e:
        raise RuntimeError(f"Failed to run Nmap scan: {e}")
