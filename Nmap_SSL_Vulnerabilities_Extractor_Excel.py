import re
import pandas as pd

def parse_nmap_output(file_path):
    """Parses nmap ssl-enum-ciphers output to extract relevant information."""
    results = {}
    
    with open(file_path, "r", encoding="utf-8") as file:
        content = file.readlines()
    
    current_host = ""
    current_port = ""
    current_protocol = ""
    vulnerabilities = {}
    
    for line in content:
        line = line.strip()
        
        # Detect host and port
        host_match = re.match(r"Nmap scan report for ([\w\.-]+) \((\d+\.\d+\.\d+\.\d+)\)", line)
        if host_match:
            if current_host and vulnerabilities:
                results[f"{current_host}:{current_port}"] = vulnerabilities
            current_host = host_match.group(1)
            vulnerabilities = {
                "SWEET32": "Not Vulnerable",
                "POODLE": "Not Vulnerable",
                "DROWN": "Not Vulnerable",
                "FREAK": "Not Vulnerable",
                "LOGJAM": "Not Vulnerable",
                "CRIME": "Not Vulnerable",
                "BEAST": "Not Vulnerable"
            }
        
        port_match = re.match(r"(\d+)/tcp", line)
        if port_match:
            current_port = port_match.group(1)
        
        # Detect protocol version (e.g., TLSv1.0, TLSv1.1, etc.)
        protocol_match = re.match(r"\|\s+(TLSv[\d.]+):", line)
        if protocol_match:
            current_protocol = protocol_match.group(1)
        
        # Detect ciphers used and add reasons
        if "3DES_EDE_CBC_SHA" in line:
            vulnerabilities["SWEET32"] = "VULNERABLE - Uses 64-bit block cipher 3DES, vulnerable to SWEET32 attack."
        if "EXPORT" in line:
            vulnerabilities["FREAK"] = "VULNERABLE - Supports EXPORT-grade RSA ciphers, vulnerable to FREAK attack."
        if "64-bit block cipher" in line:
            vulnerabilities["SWEET32"] = "VULNERABLE - Uses 64-bit block ciphers, making it vulnerable to SWEET32."
        if "NULL compression" in line:
            vulnerabilities["CRIME"] = "VULNERABLE - TLS compression is enabled, making it vulnerable to CRIME attack."
        if "CBC" in line and current_protocol == "TLSv1.0":
            vulnerabilities["BEAST"] = "VULNERABLE - CBC ciphers used in TLS 1.0, making it vulnerable to BEAST attack."
        
        # Detect POODLE vulnerability (if SSLv3 is found)
        if "SSLv3" in line:
            vulnerabilities["POODLE"] = "VULNERABLE - SSLv3 detected, vulnerable to POODLE attack."
        
        # Detect DROWN vulnerability (if SSLv2 is found)
        if "SSLv2" in line:
            vulnerabilities["DROWN"] = "VULNERABLE - SSLv2 detected, vulnerable to DROWN attack."
    
    if current_host and vulnerabilities:
        results[f"{current_host}:{current_port}"] = vulnerabilities
    
    return results

def generate_report(results, output_file):
    """Generates an Excel report of detected vulnerabilities."""
    data = []
    for host, vulnerabilities in results.items():
        row = {"IP/Domain": host}
        row.update(vulnerabilities)
        data.append(row)
    
    df = pd.DataFrame(data)
    df.to_excel(output_file, index=False)
    print(f"Report saved to {output_file}")

if __name__ == "__main__":
    file_path = input("Enter the path to the Nmap output file: ")
    output_file = input("Enter the path for the Excel output file (default: Nmap_SSL_vulnerabilities.xlsx): ")
    if not output_file:
        output_file = "Nmap_SSL_vulnerabilities.xlsx"
    
    results = parse_nmap_output(file_path)
    generate_report(results, output_file)
