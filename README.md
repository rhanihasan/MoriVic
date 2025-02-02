# MoriVic
Morivic is an automated reconnaissance tool that integrates Shodan, Nmap, and Nuclei to identify and assess security risks in publicly exposed assets. It simplifies the process of discovering open ports, vulnerabilities, and misconfigurations.


**Morivic** automates reconnaissance using:
- **Shodan** for asset discovery
- **Nmap** for deep port scanning
- **Nuclei** for vulnerability detection

## 📌 Features
- Search **Shodan** for IPs, ports, and vulnerabilities
- Perform **Nmap** scans on found assets
- Detect vulnerabilities using **Nuclei**

## 🚀 Installation
```sh
git clone https://github.com/yourusername/morivic.git
cd morivic
pip install -r requirements.txt
