# Nmap SSL Vulnerabilities Extractor

**Overview**

This script parses Nmap scan results and extracts SSL/TLS vulnerabilities for open ports using the ssl-enum-ciphers and ssl-cert scripts. It processes detected SSL services, checks for known vulnerabilities, and exports the results to an Excel file.

**Features**

* Parses Nmap scan reports to extract SSL/TLS-related details
* Detects vulnerabilities like SWEET32, POODLE, DROWN, FREAK, LOGJAM, CRIME, and BEAST
* Identifies deprecated SSL/TLS protocols
* Check SSL certificate expiration status
* Saves results to an Excel file (.xlsx)

**Requirements**

* Python 3.x
* Required libraries:
  * pandas
  * re
  * datetime

**You can install the required dependencies using:**
```
pip install pandas
```

**Usage**

Run an Nmap scan with SSL-related scripts:
```
nmap -sS -Pn --script=ssl-enum-ciphers,ssl-cert -oN sslcert.txt --open <TARGET_IP>
```
```
nmap -sS -Pn --script=ssl-enum-ciphers,ssl-cert -oN sslcert.txt --open 198.12.242.91
```

```
python Nmap_SSL_Vulnerabilities_Extractor_Excel.py
Enter the path to the Nmap output file: sslcert.txt
Enter the path for the Excel output file (default: Nmap_SSL_vulnerabilities.xlsx):
```

**Output**


![image](https://github.com/user-attachments/assets/cdc3e596-10d1-4d26-9986-5c489a6a15b2)
