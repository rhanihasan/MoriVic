import shodan
import time
import nmap
import subprocess
import argparse

# Argument Parser
parser = argparse.ArgumentParser(description="Automate Shodan, Nmap, and Nuclei Scanning")
parser.add_argument("-a", "--api", required=True, help="Shodan API Key")
parser.add_argument("-d", "--domain", required=True, help="Target domain for scanning")
args = parser.parse_args()

# Shodan API Key
api = shodan.Shodan(args.api)
search = args.domain  # Domain input from command-line argument

def request_search_from_shodan():
    page = 1  # Start with the first page
    
    with open("shodan_results.txt", "w") as result_file, open("nmap_input.txt", "w") as nmap_file, open("nuclei_input.txt", "w") as nuclei_file:
        while True:
            try:
                print(f"Searching '{search}' on page {page}...")
                shodan_search_results = api.search(search, page=page)
                
                if page == 1:
                    print(f"Total search results: {shodan_search_results['total']}")

                for match in shodan_search_results["matches"]:
                    ip = match.get('ip_str', 'N/A')
                    port = match.get('port', 'N/A')
                    vulns = match.get('vulns', [])
                    
                    print(f"IP Address: {ip}, Open Port: {port}")
                    result_file.write(f"IP: {ip}, Port: {port}\n")
                    nmap_file.write(f"{ip}:{port}\n")
                    
                    if vulns:
                        print("Vulnerabilities:")
                        for vuln in vulns:
                            print(f" - {vuln}")
                            result_file.write(f" - CVE {vuln}\n")
                    else:
                        print("No Vulnerabilities found")
                    
                    print("-" * 30)
                    result_file.write('-' * 30 + '\n')
                
                if len(shodan_search_results['matches']) < 100:
                    print("The results are under 100, stopping...")
                    break
                
                page += 1
            except shodan.APIError as apierror:
                print(f"Error: {apierror}")
                break
            except Exception as exceptions:
                print(f"Unexpected error: {exceptions}")
                break

def run_nmap_scan():
    nm = nmap.PortScanner()
    with open("nmap_input.txt", "r") as nmap_file, open("nmap_results.txt", "w") as results_files, open("nuclei_input.txt", "w") as nuclei_file:
        for line in nmap_file:
            ip, port = line.strip().split(":")
            print(f"Scanning {ip} on port {port}")
            
            try:
                scan_results = nm.scan(hosts=ip, arguments='-p- -sV -T4 --open -Pn -sC --reason')
                results_files.write(f"Results for {ip}:{port}\n")
                
                for protocol in nm[ip].all_protocols():
                    ports = nm[ip][protocol].keys()
                    for p in ports:
                        state = nm[ip][protocol][p]["state"]
                        service = nm[ip][protocol][p]['name']
                        product = nm[ip][protocol][p].get('product', 'Unknown')
                        reason = nm[ip][protocol][p].get('reason', 'Unknown')
                        print(f"Port: {p}/{protocol}, State: {state}, Service: {service}, Reason: {reason}, Product: {product}")
                        
                        if service in ["http", "https"] or int(p) in [80, 443, 8080, 8443, 8000, 8888, 3000, 5000, 4443, 10443]:
                            protocol = "https" if service == "https" or int(p) in [443, 8443, 4443, 10443] else "http"
                            nuclei_file.write(f"{protocol}://{ip}:{p}\n")
                
                results_files.write('-' * 30 + '\n')
            except Exception as e:
                print(f"Failed to scan {ip}:{port} - {e}\n")
                results_files.write(f"Failed to scan {ip}:{port} - {e}\n")
                results_files.write('-' * 30 + '\n')

def run_nuclei_scan():
    try:
        print("Running Nuclei on the generated input...")
        subprocess.run(["nuclei", "-l", "nuclei_input.txt", "-nt", "-o", "nuclei_results.txt"], check=True)
        print("Nuclei scan completed. Results saved in nuclei_results.txt.")
    except FileNotFoundError:
        print("Error: Nuclei is not installed or not found in PATH.")
    except subprocess.CalledProcessError as e:
        print(f"Nuclei scan failed: {e}")
    except Exception as e:
        print(f"Unexpected error while running Nuclei: {e}")

# Run Scanning Stages
request_search_from_shodan()
run_nmap_scan()
run_nuclei_scan()
