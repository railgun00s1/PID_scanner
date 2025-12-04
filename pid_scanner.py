# ==============================================================================
#  CYBER DEFENSE TOOLKIT
#  Version: 5.0
#  Developer: DCR
#  Description: Process Analyzer, Threat Intelligence Integration, and automated
#               Containment (Kill/Suspend) for Windows Forensic Analysis.
# ==============================================================================

import psutil
import hashlib
import requests
import sys
import os
import time
import datetime

# ==========================================
# CONFIGURATION
# ==========================================
VT_API_KEY = 'ENTER YOUR VIRUSTOTAL API KEY HERE'
HA_API_KEY = 'ENTER YOUR HYBRID ANALYSIS API KEY HERE'
# ==========================================

def get_file_hash(filepath):
    sha256_hash = hashlib.sha256()
    try:
        with open(filepath, "rb") as f:
            for byte_block in iter(lambda: f.read(4096), b""):
                sha256_hash.update(byte_block)
        return sha256_hash.hexdigest()
    except Exception:
        return None

def check_virustotal(file_hash):
    print(f"[*] Querying VirusTotal...")
    url = f"https://www.virustotal.com/api/v3/files/{file_hash}"
    headers = {"x-apikey": VT_API_KEY}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            return response.json()['data']['attributes']['last_analysis_stats']
        elif response.status_code == 404:
            return "Not Found"
        else:
            return f"Error {response.status_code}"
    except Exception as e:
        return f"Error: {e}"

def check_hybrid_analysis(file_hash):
    print(f"[*] Querying Hybrid Analysis...")
    url = f"https://www.hybrid-analysis.com/api/v2/overview/{file_hash}"
    headers = {"api-key": HA_API_KEY, "User-Agent": "Falcon Sandbox"}
    try:
        response = requests.get(url, headers=headers)
        if response.status_code == 200:
            json_resp = response.json()
            return {'verdict': json_resp.get('verdict', 'unknown'), 'threat_score': json_resp.get('threat_score', 'N/A')}
        elif response.status_code == 404:
            return "Not Found"
        else:
            return f"Error {response.status_code}"
    except Exception as e:
        return f"Error: {e}"

def get_process_ports(proc):
    ports = []
    try:
        connections = proc.connections(kind='inet')
        for conn in connections:
            if conn.laddr:
                ports.append(conn.laddr.port)
    except (psutil.AccessDenied, psutil.ZombieProcess):
        pass
    return list(set(ports))

def get_process_runtime(proc):
    try:
        create_time = proc.create_time()
        uptime_seconds = time.time() - create_time
        return str(datetime.timedelta(seconds=int(uptime_seconds)))
    except Exception:
        return "Unknown"

def print_process_tree(proc):
    tree = []
    try:
        curr = proc
        while curr:
            tree.append(curr)
            curr = curr.parent()
    except (psutil.NoSuchProcess, psutil.AccessDenied):
        pass
    
    print("\n   PROCESS EXECUTION TREE (Lineage):")
    indent = "   "
    for i, p in enumerate(reversed(tree)):
        try:
            print(f"{indent * (i+1)} └─ {p.name()} (PID: {p.pid})")
        except (psutil.ZombieProcess, psutil.NoSuchProcess):
            print(f"{indent * (i+1)} └─ [Terminated Process]")

def investigate_target(pid):
    try:
        proc = psutil.Process(pid)
        exe_path = proc.exe()
        runtime = get_process_runtime(proc)
        
        print(f"\n[+] Investigating PID: {pid} ({proc.name()})")
        print(f"[+] Path:    {exe_path}")
        print(f"[+] Runtime: {runtime}")
        print_process_tree(proc)

        # 1. Hash
        file_hash = get_file_hash(exe_path)
        if not file_hash:
            print("[!] Could not hash file.")
            return

        print(f"\n[+] SHA256: {file_hash}")
        
        # 2. Check APIs
        vt_result = check_virustotal(file_hash)
        ha_result = check_hybrid_analysis(file_hash)
        
        # 3. Report
        print("\n" + "="*45)
        print("   MULTI-SOURCE THREAT REPORT")
        print("="*45)
        
        print(f"--- VIRUSTOTAL ---")
        if isinstance(vt_result, dict):
            print(f"Malicious:  {vt_result['malicious']}")
            print(f"Suspicious: {vt_result['suspicious']}")
            print(f"Clean:      {vt_result['harmless']}")
        else:
            print(f"Result: {vt_result}")

        print("-" * 45)

        print(f"--- HYBRID ANALYSIS ---")
        if isinstance(ha_result, dict):
            print(f"Verdict:      {ha_result['verdict'].upper()}")
            print(f"Threat Score: {ha_result['threat_score']}/100")
        else:
            print(f"Result: {ha_result}")
        print("="*45)

        # 4. Action Menu
        while True:
            action = input("\n[1] Kill  [2] Pause  [3] Resume  [4] Ignore: ")
            if action == '1':
                proc.terminate()
                print("[+] Process Terminated.")
                time.sleep(1)
                break
            elif action == '2':
                proc.suspend()
                print("[+] Process PAUSED.")
            elif action == '3':
                proc.resume()
                print("[+] Process RESUMED.")
            elif action == '4':
                break
            
    except psutil.NoSuchProcess:
        print(f"[!] PID {pid} no longer exists.")
    except psutil.AccessDenied:
        print("[!] Access Denied. Run as Admin.")
    except Exception as e:
        print(f"[!] Error: {e}")

def list_detailed_processes():
    print(f"\n{'PID':<8} {'Name':<25} {'Ports':<20} {'Path'}")
    print("=" * 90)
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pid = proc.info['pid']
            name = proc.info['name'] or "Unknown"
            exe = proc.info['exe'] or "Access Denied"
            port_list = get_process_ports(proc)
            ports_str = str(port_list) if port_list else "-"
            print(f"{pid:<8} {name[:24]:<25} {ports_str[:19]:<20} {exe}")
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    print("=" * 90)

def find_pids_by_name(name_query):
    matches = []
    print(f"\n[*] Searching for processes containing '{name_query}'...")
    
    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            if name_query.lower() in proc.info['name'].lower():
                matches.append(proc)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
            
    if not matches:
        print("[-] No matching processes found.")
        return None
    
    if len(matches) == 1:
        return matches[0].info['pid']
    else:
        print(f"\n[!] Multiple processes found for '{name_query}':")
        print(f"{'PID':<8} {'Name':<25} {'Path'}")
        print("-" * 60)
        for p in matches:
            print(f"{p.info['pid']:<8} {p.info['name']:<25} {p.info['exe']}")
        print("-" * 60)
        
        target = input("Enter the specific PID to investigate: ")
        if target.isdigit():
            return int(target)
        return None

def find_pid_by_port(target_port):
    print(f"\n[*] Scanning for process on Port {target_port}...")
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            ports = get_process_ports(proc)
            if target_port in ports:
                return proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None

def process_menu_loop():
    list_detailed_processes()
    
    while True:
        print("\n[A]CTION MENU:")
        print("1. Investigate by PID")
        print("2. Investigate by Process Name")
        print("3. Investigate by Port")
        print("4. Refresh Process List")
        print("5. Back to Main Menu")
        
        choice = input("Select Option: ")
        
        if choice == '1':
            target = input("Enter PID: ")
            if target.isdigit(): investigate_target(int(target))
            
        elif choice == '2':
            name_query = input("Enter Process Name (e.g., notepad): ")
            found_pid = find_pids_by_name(name_query)
            if found_pid:
                investigate_target(found_pid)
                
        elif choice == '3':
            port = input("Enter Port: ")
            if port.isdigit():
                found_pid = find_pid_by_port(int(port))
                if found_pid: investigate_target(found_pid)
                else: print("[-] No process found on that port.")
                
        elif choice == '4':
            print("\n[*] Refreshing process list...")
            list_detailed_processes()
            
        elif choice == '5':
            print("[*] Returning to Main Menu...")
            break
        else:
            print("Invalid selection.")

def main_menu():
    while True:
        print("\n==================================")
        print("   CYBER DEFENSE TOOLKIT v5.0")
        print("   Developed by: DCR")
        print("==================================")
        print("a. List Running Processes")
        print("b. Manual Hash Check")
        print("q. Quit")
        choice = input("\nSelect Option: ").lower()
        if choice == 'a': process_menu_loop()
        elif choice == 'b':
            h = input("\nEnter SHA256: ").strip()
            print(f"VT: {check_virustotal(h)}")
            print(f"HA: {check_hybrid_analysis(h)}")
        elif choice == 'q': sys.exit()

if __name__ == "__main__":
    main_menu()
