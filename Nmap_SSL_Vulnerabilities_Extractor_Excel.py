import re
import pandas as pd

def parse_nmap_output(file_path):
    """Parses nmap ssl-enum-ciphers output to extract relevant information about SSL/TLS vulnerabilities."""
    results = {}
    
    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()
    
    # Extract hostname and IP
    host_match = re.search(r"Nmap scan report for ([\w\.-]+)(?: \((\d+\.\d+\.\d+\.\d+)\))?", content)
    if not host_match:
        print("Could not find host information in the Nmap output.")
        return results
        
    hostname = host_match.group(1)
    ip = host_match.group(2) if host_match.group(2) else hostname
    
    # Find all ports sections
    port_pattern = re.compile(r"(\d+)/tcp\s+(?:open|closed|filtered)\s+(\w+(?:-\w+)?)")
    ssl_enum_pattern = re.compile(r"\| ssl-enum-ciphers:")
    
    lines = content.split('\n')
    current_port = None
    collecting_ssl_info = False
    ssl_info = ""
    
    # Initialize results for the hostname
    results[hostname] = {}
    
    for i, line in enumerate(lines):
        # Check for port information
        port_match = port_pattern.search(line)
        if port_match:
            # If we were collecting SSL info for a previous port, process it now
            if collecting_ssl_info and current_port:
                process_ssl_vulnerabilities(hostname, current_port, ssl_info, results)
            
            # Reset for new port
            current_port = port_match.group(1)
            collecting_ssl_info = False
            ssl_info = ""
        
        # Check if this line starts SSL enumeration for the current port
        if ssl_enum_pattern.search(line) and current_port:
            collecting_ssl_info = True
            ssl_info = line + "\n"
        # If we're collecting SSL info, add this line
        elif collecting_ssl_info:
            ssl_info += line + "\n"
    
    # Process the last port if needed
    if collecting_ssl_info and current_port:
        process_ssl_vulnerabilities(hostname, current_port, ssl_info, results)
    
    # Remove ports without SSL info
    for host in list(results.keys()):
        if not results[host]:
            del results[host]
    
    return results

def process_ssl_vulnerabilities(hostname, port, ssl_info, results):
    """Process SSL information for a specific port and detect vulnerabilities."""
    # Initialize vulnerabilities as "Not Vulnerable"
    vulnerabilities = {
        "SWEET32": "Not Vulnerable",
        "POODLE": "Not Vulnerable",
        "DROWN": "Not Vulnerable",
        "FREAK": "Not Vulnerable",
        "LOGJAM": "Not Vulnerable",
        "CRIME": "Not Vulnerable",
        "BEAST": "Not Vulnerable"
    }
    
    # Check for SWEET32 (3DES or DES ciphers)
    if re.search(r"(?:_3DES_|_DES_)", ssl_info, re.IGNORECASE):
        vulnerabilities["SWEET32"] = "VULNERABLE - Uses 64-bit block cipher (3DES/DES)"
    
    # Check for POODLE (SSLv3 protocol)
    if re.search(r"SSLv3:", ssl_info, re.IGNORECASE):
        vulnerabilities["POODLE"] = "VULNERABLE - SSLv3 is enabled"
    
    # Check for DROWN (SSLv2 protocol)
    if re.search(r"SSLv2:", ssl_info, re.IGNORECASE):
        vulnerabilities["DROWN"] = "VULNERABLE - SSLv2 is enabled"
    
    # Check for FREAK (Export-grade ciphers)
    if re.search(r"(?:_EXPORT_|_EXP_)", ssl_info, re.IGNORECASE):
        vulnerabilities["FREAK"] = "VULNERABLE - Export-grade ciphers enabled"
    
    # Check for LOGJAM (DHE with weak parameters < 2048 bits)
    dh_matches = re.findall(r"dh (\d+)", ssl_info)
    for dh_size in dh_matches:
        if int(dh_size) < 2048:
            vulnerabilities["LOGJAM"] = f"VULNERABLE - DHE using weak {dh_size}-bit parameters"
            break
    
    # Check for CRIME (TLS compression)
    if "compressors:" in ssl_info and not "NULL" in ssl_info.split("compressors:")[1].split("\n")[0]:
        vulnerabilities["CRIME"] = "VULNERABLE - TLS compression is enabled"
    
    # Check for BEAST (CBC ciphers in TLSv1.0)
    if re.search(r"TLSv1\.0:.*?_CBC_", ssl_info, re.DOTALL):
        vulnerabilities["BEAST"] = "VULNERABLE - CBC ciphers with TLSv1.0"
    
    # Add to results
    results[hostname][port] = vulnerabilities

def generate_report(results, output_file):
    """Generates an Excel report of detected vulnerabilities."""
    data = []
    
    for host, ports in results.items():
        for port, vulnerabilities in ports.items():
            row = {"IP/Domain": f"{host}:{port}"}
            row.update(vulnerabilities)
            data.append(row)
    
    if data:
        df = pd.DataFrame(data)
        # Reorder columns to match the requested output format
        column_order = ["IP/Domain", "SWEET32", "POODLE", "DROWN", "FREAK", "LOGJAM", "CRIME", "BEAST"]
        df = df[column_order]
        df.to_excel(output_file, index=False)
        print(f"Report successfully saved to {output_file}")
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
