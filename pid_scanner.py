# ==============================================================================
#  CYBER DEFENSE TOOLKIT
#  Version: 6.3
#  Developer: rlgn00s1
# ==============================================================================

import psutil
import hashlib
import requests
import sys
import os
import time
import socket
import datetime
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn

# Initialize Rich Console
console = Console()

# ==========================================
# CONFIGURATION
# ==========================================
# NOTE: Be careful sharing code with real API keys publicly.
VT_API_KEY = 'a145b277b8c83de1ef410fe7370649ce84e9e8253b6cc98bed2d0c285ed7faa1'
HA_API_KEY = 'qkz5eeca599fe34307ttbummf2b25a838rr1h02f8d018b14z3wqn1b72877395a'
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

def find_pid_by_port(target_port):
    """
    Scans all processes to find which one is listening on the target port.
    """
    console.print(f"\n[dim][*] Scanning for process on Port {target_port}...[/dim]")
    for proc in psutil.process_iter(['pid', 'name']):
        try:
            ports = get_process_ports(proc)
            if target_port in ports:
                return proc.info['pid']
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    return None

def display_process_tree(proc):
    tree_str = ""
    try:
        curr = proc
        lineage = []
        while curr:
            lineage.append(curr)
            curr = curr.parent()
        
        indent = "  "
        for i, p in enumerate(reversed(lineage)):
            try:
                tree_str += f"\n{indent * (i)} └─ [bold cyan]{p.name()}[/bold cyan] (PID: {p.pid})"
            except:
                tree_str += f"\n{indent * (i)} └─ [Terminated]"
    except:
        tree_str = "Unable to map tree."
    return tree_str

def investigate_target(pid):
    try:
        proc = psutil.Process(pid)
        exe_path = proc.exe()
        
        console.print(f"\n[bold yellow][+] Investigating PID: {pid} ({proc.name()})[/bold yellow]")
        
        # Hash
        file_hash = get_file_hash(exe_path)
        if not file_hash:
            console.print("[bold red][!] Could not hash file (Access Denied).[/bold red]")
            return

        console.print(f"[dim]SHA256: {file_hash}[/dim]")
        
        # API Checks with Spinner
        with console.status("[bold green]Querying Threat Intelligence APIs...[/bold green]", spinner="dots"):
            vt_result = check_virustotal(file_hash)
            ha_result = check_hybrid_analysis(file_hash)
        
        # Display Results in Panels
        vt_text = ""
        if isinstance(vt_result, dict):
            vt_text += f"[bold red]Malicious:  {vt_result['malicious']}[/bold red]\n"
            vt_text += f"[yellow]Suspicious: {vt_result['suspicious']}[/yellow]\n"
            vt_text += f"[green]Clean:      {vt_result['harmless']}[/green]"
        else:
            vt_text = str(vt_result)

        ha_text = ""
        if isinstance(ha_result, dict):
            verdict_color = "red" if ha_result['verdict'] == 'malicious' else "green"
            ha_text += f"Verdict:      [{verdict_color}]{ha_result['verdict'].upper()}[/{verdict_color}]\n"
            ha_text += f"Threat Score: {ha_result['threat_score']}/100"
        else:
            ha_text = str(ha_result)

        # Print Side-by-Side Grid or stacked
        console.print(Panel(vt_text, title="[bold]VirusTotal[/bold]", border_style="blue"))
        console.print(Panel(ha_text, title="[bold]Hybrid Analysis[/bold]", border_style="magenta"))
        
        console.print(Panel(display_process_tree(proc), title="Process Lineage", border_style="white"))

        # Action Menu
        action = console.input("\n[bold white][[1] Kill  [2] Pause  [3] Resume  [4] Return]: [/bold white]")
        if action == '1':
            proc.terminate()
            console.print("[bold red][+] Process Terminated.[/bold red]")
            time.sleep(1)
        elif action == '2':
            proc.suspend()
            console.print("[bold yellow][+] Process PAUSED.[/bold yellow]")
        elif action == '3':
            proc.resume()
            console.print("[bold green][+] Process RESUMED.[/bold green]")
            
    except psutil.NoSuchProcess:
        console.print(f"[bold red][!] PID {pid} no longer exists.[/bold red]")
    except psutil.AccessDenied:
        console.print("[bold red][!] Access Denied. Run as Admin.[/bold red]")
    except Exception as e:
        console.print(f"[bold red][!] Error: {e}[/bold red]")

def list_detailed_processes():
    table = Table(title="Active Processes", show_header=True, header_style="bold magenta")
    table.add_column("PID", style="cyan", width=8)
    table.add_column("Name", style="white", width=25)
    table.add_column("Ports", style="green", width=15)
    table.add_column("Path", style="dim", overflow="fold")

    for proc in psutil.process_iter(['pid', 'name', 'exe']):
        try:
            pid = str(proc.info['pid'])
            name = proc.info['name'] or "Unknown"
            exe = proc.info['exe'] or "Access Denied"
            port_list = get_process_ports(proc)
            ports_str = str(port_list) if port_list else "-"
            
            table.add_row(pid, name, ports_str, exe)
        except (psutil.NoSuchProcess, psutil.AccessDenied):
            continue
    
    console.print(table)

def run_port_scan():
    """
    Active Port Scanner with Admin Checks
    """
    console.print(Panel("ACTIVE PORT SCANNER", style="bold cyan"))
    
    target_ip = console.input("[bold]Enter Target IP: [/bold]")
    try:
        target_port = int(console.input("[bold]Enter Port Number: [/bold]"))
    except ValueError:
        console.print("[bold red]Error: Port must be a number.[/bold red]")
        return

    console.print(f"[dim]Scanning {target_ip}:{target_port}...[/dim]")

    try:
        # 1. Create the socket
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        
        # 2. Set a timeout (fast scan)
        s.settimeout(2)
        
        # 3. Attempt connection
        result = s.connect_ex((target_ip, target_port))

        if result == 0:
            console.print(Panel(f"[+] Port {target_port} is [bold green]OPEN[/bold green]", border_style="green"))
        else:
            console.print(f"[-] Port {target_port} is [red]CLOSED/FILTERED[/red]")

        s.close()

    # --- ERROR HANDLING ---
    except PermissionError:
        console.print(Panel(
            "[bold red]ACCESS DENIED[/bold red]\n\n"
            "This scan requires Administrator/Root privileges.\n"
            "Please restart the tool as Admin.",
            title="ERROR",
            border_style="red"
        ))
        console.input("[dim]Press Enter to return...[/dim]")
        
    except OSError as e:
        # Windows often throws Error 10013 for access denied on sockets
        if "access is denied" in str(e).lower() or e.errno == 10013:
            console.print(Panel(
                "[bold red]ACCESS DENIED[/bold red]\n\n"
                "Windows blocked this socket connection.\n"
                "Please restart the tool as Administrator.",
                title="ERROR",
                border_style="red"
            ))
            console.input("[dim]Press Enter to return...[/dim]")
        else:
            console.print(f"[bold red]Unexpected Error: {e}[/bold red]")
            time.sleep(2)

def edr_automated_scan():
    """
    Scans running processes one by one.
    """
    console.print("\n[bold red]!!! WARNING !!![/bold red]")
    console.print("You are about to scan running processes against public APIs.")
    console.print("Free API keys have strict rate limits (usually 4 requests/minute).")
    console.print("This tool will add a 15-second delay between checks to prevent bans.")
    
    confirm = console.input("Do you want to proceed? (y/n): ")
    if confirm.lower() != 'y':
        return

    table = Table(title="Live EDR Scan Results", show_header=True)
    table.add_column("PID", style="cyan")
    table.add_column("Name", style="white")
    table.add_column("VT Malicious", style="red")
    table.add_column("Verdict", style="bold")

    with Progress(SpinnerColumn(), TextColumn("[progress.description]{task.description}"), transient=True) as progress:
        task = progress.add_task("[green]Scanning processes...", total=None)
        
        count = 0
        for proc in psutil.process_iter(['pid', 'name', 'exe']):
            try:
                # OPTIONAL: Limit scan to 10 items for demo purposes
                # if count >= 10: break 

                pid = proc.info['pid']
                name = proc.info['name']
                exe = proc.info['exe']
                
                if not exe: continue # Skip system processes we can't read
                
                progress.update(task, description=f"Hashing {name} ({pid})...")
                file_hash = get_file_hash(exe)
                
                if file_hash:
                    progress.update(task, description=f"Querying API for {name}...")
                    vt_result = check_virustotal(file_hash)
                    
                    mal_count = 0
                    if isinstance(vt_result, dict):
                        mal_count = vt_result.get('malicious', 0)
                    
                    # Determine Status
                    if mal_count > 0:
                        status = "[red]THREAT DETECTED[/red]"
                    else:
                        status = "[green]CLEAN[/green]"

                    console.print(f"PID: {pid} | {name} | Malicious: {mal_count} | {status}")
                    
                    # RATE LIMIT SLEEP
                    time.sleep(15) 
                    count += 1
                    
            except (psutil.NoSuchProcess, psutil.AccessDenied):
                continue

    console.print("[bold green]Scan Complete.[/bold green]")

def process_menu_loop():
    while True:
        list_detailed_processes()
        print("\n")
        
        # MENU UPDATED: Network Scanner moved here (Option 4)
        menu_text = (
            "[1] Investigate by PID\n"
            "[2] Investigate by Name\n"
            "[3] Investigate by Port (Find Process)\n"
            "[4] Active Port Scanner (Check IP)\n"
            "[5] EDR Mass Scan (Auto-Analyze)\n"
            "[6] Return"
        )
        
        console.print(Panel(menu_text, title="Process Options", expand=False))
        
        choice = console.input("[bold cyan]Select Option: [/bold cyan]")
        
        if choice == '1':
            target = input("Enter PID: ")
            if target.isdigit(): investigate_target(int(target))
        elif choice == '2':
            # Placeholder for name search logic
            pass 
        elif choice == '3':
            # FIND PID BY PORT
            port = console.input("Enter Port: ")
            if port.isdigit():
                found_pid = find_pid_by_port(int(port))
                if found_pid: 
                    investigate_target(found_pid)
                else: 
                    console.print("[bold red][-] No process found on that port.[/bold red]")
                    time.sleep(2)
        elif choice == '4':
            # NEW: ACTIVE SCANNER MOVED HERE
            run_port_scan()
        elif choice == '5':
            edr_automated_scan()
        elif choice == '6':
            break

def main_menu():
    while True:
        console.clear()
        console.print(Panel.fit(
            "   [bold green]CYBER DEFENSE TOOLKIT v6.3[/bold green]\n   Developed by: rlgn",
            border_style="green"
        ))
        
        # MAIN MENU CLEANED UP
        console.print("[bold]1.[/bold] List & Analyze Processes")
        console.print("[bold]2.[/bold] Manual Hash Check")
        console.print("[bold]q.[/bold] Quit")
        
        choice = console.input("\n[bold cyan]Select Option: [/bold cyan]").lower()
        
        if choice == '1':
            process_menu_loop()
        elif choice == '2':
            h = console.input("\n[yellow]Enter SHA256: [/yellow]").strip()
            console.print(f"VT: {check_virustotal(h)}")
            console.input("[dim]Press Enter to continue...[/dim]")
        elif choice == 'q':
            sys.exit()

if __name__ == "__main__":
    main_menu()
