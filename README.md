# MoriVic

**MoriVic** is an automated reconnaissance tool that integrates **Shodan**, **Nmap**, and **Nuclei** to identify and assess security risks in publicly exposed assets. It simplifies the process of discovering open ports, vulnerabilities, and misconfigurations.

---

## 🔥 Key Features
- **Shodan Asset Discovery** 🕵️‍♂️  
  - Searches **Shodan** for exposed devices, IPs, open ports, and known vulnerabilities.
- **Nmap Port Scanning** ⚡  
  - Performs **aggressive scanning** to enumerate open services and detect misconfigurations.
- **Nuclei Vulnerability Detection** 🛡️  
  - Uses **Nuclei** to find potential security flaws and CVEs.

---

## 🚀 Installation

### **Clone the Repository**
```sh
 git clone https://github.com/rhanihasan/MoriVic.git
 cd MoriVic
```

### **Install Dependencies**
```sh
pip install -r requirements.txt
```

### **Ensure Required Tools Are Installed**
- **Nmap** (for network scanning):
  ```sh
  sudo apt install nmap
  ```
- **Nuclei** (for vulnerability scanning):
  ```sh
  go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
  ```

---

## 🎯 Usage
Run the tool with your **Shodan API key** and **target domain**:
```sh
python3 main.py -a YOUR_SHODAN_API_KEY -d TARGET_DOMAIN
```

### **Example:**
```sh
python3 main.py -a APIKEY -d tesla.com
```

---

## 📂 Output Files
- `results/shodan_results.txt` - Shodan scan results.
- `results/nmap_results.txt` - Nmap scan output.
- `results/nuclei_results.txt` - Nuclei vulnerability findings.

---

## 🛠 Requirements
- **Python 3.x**
- **Shodan API Key** (Get it from [Shodan](https://account.shodan.io/))
- **Nmap** (`sudo apt install nmap`)
- **Nuclei** (`go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest`)

---

## ⚠️ Disclaimer
This tool is intended for **ethical hacking and security research**. Ensure you have **legal authorization** before scanning any targets.

---

## 📜 License
**MoriVic** is licensed under the **MIT License**, allowing free use, modification, and distribution.

---

## 🤝 Contributing
Pull requests are welcome. For major changes, please open an issue first to discuss what you would like to change.

---

## 📞 Contact
For inquiries, contact [your email or GitHub Issues](https://github.com/rhanihasan/MoriVic/issues).

