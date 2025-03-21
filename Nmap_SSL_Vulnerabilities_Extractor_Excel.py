import re
import pandas as pd
import sys
import os

def parse_nmap_output(file_path, debug=False):
    results = {}
    debug_info = {}

    with open(file_path, "r", encoding="utf-8") as file:
        content = file.read()

    host_pattern = re.compile(r"Nmap scan report for ([\w\.-]+)(?: \((\d+\.\d+\.\d+\.\d+)\))?")
    port_pattern = re.compile(r"(\d+)/tcp\s+open\s+(\w+(?:-\w+)?)")
    ssl_enum_pattern = re.compile(r"\|\s+ssl-enum-ciphers:")

    host_matches = list(host_pattern.finditer(content))
    for i, host_match in enumerate(host_matches):
        hostname = host_match.group(1)
        ip = host_match.group(2) if host_match.group(2) else hostname
        start_pos = host_match.end()
        end_pos = host_matches[i + 1].start() if i + 1 < len(host_matches) else len(content)
        host_section = content[start_pos:end_pos]

        results[ip] = {}
        debug_info[ip] = {}
        
        current_port = None
        collecting_ssl_info = False
        ssl_info = ""

        for line in host_section.split('\n'):
            port_match = port_pattern.search(line)
            if port_match:
                if collecting_ssl_info and current_port:
                    process_ssl_vulnerabilities(ip, current_port, ssl_info, results, debug_info)
                current_port = port_match.group(1)
                collecting_ssl_info = False
                ssl_info = ""

            if ssl_enum_pattern.search(line) and current_port:
                collecting_ssl_info = True
                ssl_info = line + "\n"
            elif collecting_ssl_info:
                ssl_info += line + "\n"

        if collecting_ssl_info and current_port:
            process_ssl_vulnerabilities(ip, current_port, ssl_info, results, debug_info)

    return results, debug_info

def process_ssl_vulnerabilities(ip, port, ssl_info, results, debug_info):
    vulnerabilities = {}
    ssl_info_lower = ssl_info.lower()
    
    vulnerability_checks = {
        "SWEET32": ["3des", "des-cbc3", "des-cbc", "triple-des", "des3"],
        "POODLE": ["sslv3", "ssl v3"],
        "DROWN": ["sslv2", "ssl v2"],
        "FREAK": ["export", "exp-", "exp_", "export-"],
        "CRIME": ["compression: enabled", "compressors:"],
    }
    
    for vuln, patterns in vulnerability_checks.items():
        if any(pattern in ssl_info_lower for pattern in patterns):
            vulnerabilities[vuln] = "VULNERABLE"
    
    dh_matches = re.findall(r"(?:dh|diffie.hellman).{0,20}?(\d+)\s*bits?", ssl_info_lower)
    for dh_size in dh_matches:
        if int(dh_size) < 2048:
            vulnerabilities["LOGJAM"] = f"VULNERABLE - Weak {dh_size}-bit DH"
            break
    
    has_tlsv1 = "tlsv1.0" in ssl_info_lower or "tls v1.0" in ssl_info_lower
    has_cbc = "cbc" in ssl_info_lower
    tlsv1_section = re.search(r"TLSv1\.0[^]*(.*?)(?:\w|\Z)", ssl_info, re.DOTALL | re.IGNORECASE)
    has_cbc_in_tlsv1 = "cbc" in tlsv1_section.group(1).lower() if tlsv1_section else False
    
    if has_tlsv1 and has_cbc_in_tlsv1:
        vulnerabilities["BEAST"] = "VULNERABLE - CBC ciphers with TLSv1.0"
    
    results[ip][port] = vulnerabilities
    debug_info[ip][port] = {
        "raw_ssl_info": ssl_info, 
        "detected_vulnerabilities": vulnerabilities,
        "cipher_checks": {
            "has_tlsv1": has_tlsv1,
            "has_cbc": has_cbc,
            "has_cbc_in_tlsv1": has_cbc_in_tlsv1
        }
    }

def generate_report(results, output_file):
    data = []
    for host, ports in results.items():
        for port, vulnerabilities in ports.items():
            row = {"IP/Domain": f"{host}:{port}"}
            row.update(vulnerabilities)
            data.append(row)
    
    df = pd.DataFrame(data)
    df.to_excel(output_file, index=False)
    print(f"Report saved: {output_file}")

if __name__ == "__main__":
    file_path = input("Enter the Nmap output file: ")
    output_file = input("Enter Excel output file (default: Nmap_SSL_vulnerabilities.xlsx): ") or "Nmap_SSL_vulnerabilities.xlsx"
    results, debug_info = parse_nmap_output(file_path, debug=True)
    generate_report(results, output_file)
