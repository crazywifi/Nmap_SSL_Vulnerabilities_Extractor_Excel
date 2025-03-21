import re
import pandas as pd
from datetime import datetime

def parse_nmap_output(file_path):
    results = {}
    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()
    host_pattern = re.compile(r"Nmap scan report for ([\w\.-]+)(?: \((\d+\.\d+\.\d+\.\d+)\))?")
    host_matches = host_pattern.finditer(content)
    
    for host_match in host_matches:
        hostname = host_match.group(1)
        ip = host_match.group(2) if host_match.group(2) else hostname
        start_pos = host_match.start()
        next_match = host_pattern.search(content, host_match.end())
        end_pos = next_match.start() if next_match else len(content)
        host_section = content[start_pos:end_pos]
        process_host(hostname, ip, host_section, results)
    
    return results

def process_host(hostname, ip, host_section, results):
    port_pattern = re.compile(r"(\d+)/tcp\s+open\s+(\w+(?:-\w+)?)")
    ssl_pattern = re.compile(r"\| ssl-enum-ciphers:|ssl-cert:")
    expiry_pattern = re.compile(r"Not valid after:\s+([\d\-:T]+)")
    
    lines = host_section.split('\n')
    current_port = None
    collecting_ssl_info = False
    ssl_info = ""
    ssl_expiry = "Unknown"
    host_key = ip
    if host_key not in results:
        results[host_key] = {}
    for i, line in enumerate(lines):
        port_match = port_pattern.search(line)
        if port_match:
            if collecting_ssl_info and current_port:
                process_ssl_vulnerabilities(host_key, current_port, ssl_info, ssl_expiry, results)
            current_port = port_match.group(1)
            collecting_ssl_info = False
            ssl_info = ""
            ssl_expiry = "Unknown"
        if ssl_pattern.search(line) and current_port:
            collecting_ssl_info = True
            ssl_info = line + "\n"
        elif collecting_ssl_info:
            ssl_info += line + "\n"
        expiry_match = expiry_pattern.search(line)
        if expiry_match:
            expiry_date_str = expiry_match.group(1)
            ssl_expiry = check_ssl_expiry(expiry_date_str)
    
    if collecting_ssl_info and current_port:
        process_ssl_vulnerabilities(host_key, current_port, ssl_info, ssl_expiry, results)

def process_ssl_vulnerabilities(hostname, port, ssl_info, ssl_expiry, results):
    vulnerabilities = {
        "SWEET32": "Not Vulnerable",
        "POODLE": "Not Vulnerable",
        "DROWN": "Not Vulnerable",
        "FREAK": "Not Vulnerable",
        "LOGJAM": "Not Vulnerable",
        "CRIME": "Not Vulnerable",
        "BEAST": "Not Vulnerable",
        "SSL Expiry": ssl_expiry,
        "Deprecated Protocols": "Not Deprecated"
    }
    
    if re.search(r"(?:_3DES_|_DES_)", ssl_info, re.IGNORECASE):
        vulnerabilities["SWEET32"] = "VULNERABLE - Uses 64-bit block cipher (3DES/DES)"
    
    if re.search(r"SSLv3:", ssl_info, re.IGNORECASE):
        vulnerabilities["POODLE"] = "VULNERABLE - SSLv3 is enabled"
    
    if re.search(r"SSLv2:", ssl_info, re.IGNORECASE):
        vulnerabilities["DROWN"] = "VULNERABLE - SSLv2 is enabled"
    
    if re.search(r"(?:_EXPORT_|_EXP_)", ssl_info, re.IGNORECASE):
        vulnerabilities["FREAK"] = "VULNERABLE - Export-grade ciphers enabled"
    
    dh_matches = re.findall(r"dh (\d+)", ssl_info)
    for dh_size in dh_matches:
        if int(dh_size) < 2048:
            vulnerabilities["LOGJAM"] = f"VULNERABLE - DHE using weak {dh_size}-bit parameters"
            break
    
    compression_section = re.search(r"compressors:\s*\n(.*?)\n", ssl_info)
    if compression_section and "NULL" not in compression_section.group(1):
        vulnerabilities["CRIME"] = "VULNERABLE - TLS compression is enabled"
    
    if re.search(r"TLSv1\.0:.*?_CBC_", ssl_info, re.DOTALL):
        vulnerabilities["BEAST"] = "VULNERABLE - CBC ciphers with TLSv1.0"
    
    if re.search(r"SSLv3|TLSv1\.0|TLSv1\.1", ssl_info, re.IGNORECASE):
        vulnerabilities["Deprecated Protocols"] = "Deprecated"
    
    results[hostname][port] = vulnerabilities

def check_ssl_expiry(expiry_date_str):
    try:
        expiry_date = datetime.strptime(expiry_date_str, "%Y-%m-%dT%H:%M:%S")
        return "Expired" if expiry_date < datetime.utcnow() else "Not Expired"
    except ValueError:
        return "Unknown"

def generate_report(results, output_file):
    data = []
    for host, ports in results.items():
        for port, vulnerabilities in ports.items():
            row = {"IP/Domain": f"{host}:{port}"}
            row.update(vulnerabilities)
            data.append(row)
    
    if data:
        df = pd.DataFrame(data)
        column_order = ["IP/Domain", "SWEET32", "POODLE", "DROWN", "FREAK", "LOGJAM", "CRIME", "BEAST", "SSL Expiry", "Deprecated Protocols"]
        df = df[column_order]
        df.to_excel(output_file, index=False)
        print(f"Report successfully saved to {output_file}")
        print(f"\nFound {len(data)} SSL/TLS services across {len(results)} hosts")
        for host in results:
            print(f"  - {host}: {len(results[host])} SSL/TLS services")
        return True
    else:
        print("No SSL/TLS services found in the scan results")
        return False

if __name__ == "__main__":
    try:
        file_path = input("Enter the path to the Nmap output file: ")
        output_file = input("Enter the path for the Excel output file (default: Nmap_SSL_vulnerabilities.xlsx): ")
        if not output_file:
            output_file = "Nmap_SSL_vulnerabilities.xlsx"
        results = parse_nmap_output(file_path)
        if results and any(results.values()):
            generate_report(results, output_file)
        else:
            print("No SSL/TLS services found in the scan results")
    except Exception as e:
        print(f"An error occurred: {str(e)}")
