import subprocess
import time
import csv
import os
import signal
import random
import ipaddress
from datetime import datetime
import shutil 


GENERATOR_IP = "192.168.188.183"    
DUT_IP = "192.168.188.182"          
SSH_USER = "kali"                   
SSH_PASSWORD = "kali"               
TEST_DURATION = 30                  
MONITOR_INTERVAL = 2                

RULE_COUNTS = list(range(0, 50001, 10000))

RESULTS_DIR = "./results/iptables"

IPTABLES_RULES_FILE = "/tmp/iptables_input_test_rules.txt"
IPERF_STREAMS = 4                   


FILENAME_BANDWIDTH = os.path.join(RESULTS_DIR, "bandwidth_vs_iptables_rules.csv")
FILENAME_CPU = os.path.join(RESULTS_DIR, "system_cpu_vs_iptables_rules.csv")
FILENAME_MEM = os.path.join(RESULTS_DIR, "system_mem_vs_iptables_rules.csv")

def run_local_command(cmd_list, check=True, timeout=60):
    print(f"Running local: {' '.join(cmd_list)}")
    try:
        result = subprocess.run(cmd_list, check=check, capture_output=True, text=True, timeout=timeout)
        return result.stdout, result.stderr
    except subprocess.CalledProcessError as e:
        print(f"ERROR executing locally {' '.join(cmd_list)}: {e}")
        print(f"Stderr: {e.stderr.strip()}")
        return None, e.stderr
    except subprocess.TimeoutExpired:
        print(f"ERROR: Timeout executing locally {' '.join(cmd_list)}")
        return None, "Timeout"
    except Exception as e:
        print(f"ERROR: Unexpected error executing locally {' '.join(cmd_list)}: {e}")
        return None, str(e)

def run_remote_command(host, user, password, cmd_str, timeout=None):
    ssh_cmd_list = ["sshpass","-p",password,"ssh","-o","StrictHostKeyChecking=no","-o","UserKnownHostsFile=/dev/null",f"{user}@{host}", cmd_str]
    print(f"Running remote via sshpass: {cmd_str}")
    try:
        effective_timeout = timeout if timeout is not None else TEST_DURATION + 30
        result = subprocess.run(ssh_cmd_list, check=True, capture_output=True, text=True, timeout=effective_timeout)
        print(f"Remote command success on {host}.")
        return result.stdout, result.stderr
    except FileNotFoundError: print(f"CRITICAL ERROR: 'sshpass' not found. Please install it."); return None, "'sshpass' not found"
    except subprocess.CalledProcessError as e:
        print(f"ERROR: Remote command failed (sshpass/ssh) to {host}: {e}")
        if e.stderr: print(f"Remote Stderr: {e.stderr.strip()}"); print("Hint: Check SSH password/permissions.")
        return None, e.stderr
    except subprocess.TimeoutExpired: print(f"ERROR: Timeout on remote command to {host}"); return None, "Timeout"
    except Exception as e: print(f"ERROR: Unexpected error on remote command to {host}: {e}"); return None, str(e)


def start_background_monitor(cmd_list):
    print(f"Starting background monitor: {' '.join(cmd_list)}")
    try:
        process = subprocess.Popen(cmd_list, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, preexec_fn=os.setsid)
        time.sleep(0.5)
        pgid = os.getpgid(process.pid)
        print(f"Monitor process started with PID: {process.pid}, PGID: {pgid}")
        return process
    except Exception as e: print(f"ERROR: Starting background monitor {' '.join(cmd_list)}: {e}"); return None

def stop_background_monitor(process):
    if not process: print("Monitor process invalid or not started."); return None, "Invalid process"
    pgid = -1
    try:
        pgid = os.getpgid(process.pid)
        if process.poll() is None:
            print(f"Stopping background monitor process group: PGID={pgid}")
            os.killpg(pgid, signal.SIGTERM)
            time.sleep(1)
            if process.poll() is None:
                print(f"Monitor PGID={pgid} did not exit via TERM, sending KILL...")
                os.killpg(pgid, signal.SIGKILL)
                time.sleep(0.5)
            stdout, stderr = process.communicate(timeout=10)
            print(f"Monitor PGID={pgid} stopped (exit code {process.returncode}).")
            return stdout, stderr
        else:
            print(f"Monitor process PID={process.pid} already finished.")
            stdout, stderr = process.communicate(timeout=5)
            return stdout, stderr
    except ProcessLookupError:
        print(f"Monitor process/group (PID={process.pid}, PGID={pgid if pgid != -1 else 'unknown'}) not found.")
        try:
            stdout, stderr = process.communicate(timeout=5)
            return stdout, stderr
        except Exception:
            return None, "Process not found and output unavailable"
    except Exception as e:
        print(f"ERROR: Stopping/communicating with monitor PID={process.pid} (PGID={pgid if pgid != -1 else 'unknown'}): {e}")
        try:
            if process and process.poll() is None:
                process.kill()
                stdout, stderr = process.communicate(timeout=5)
                return stdout, stderr
        except Exception as kill_e:
            print(f"ERROR: Failed to kill monitor PID={process.pid} directly after error: {kill_e}")
        return None, str(e)


def generate_random_ip():
    while True:
        try:
             ip_str = f"{random.randint(1, 223)}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
             ip = ipaddress.ip_address(ip_str)
             if not ip.is_private and not ip.is_loopback and not ip.is_multicast and not ip.is_link_local:
                 return ip_str
        except ValueError:
             continue

def generate_iptables_input_rules(count, filename):
    print(f"Generating {count} iptables INPUT DROP rules to {filename}...")
    try:
        with open(filename, "w") as f:
            f.write("*filter\n") 
            
            
            f.write(":INPUT - [0:0]\n")
            f.write(":FORWARD ACCEPT [0:0]\n") 
            f.write(":OUTPUT ACCEPT [0:0]\n") 
            
            for i in range(count):
                random_ip = generate_random_ip()
                
                f.write(f"-A INPUT -s {random_ip}/32 -j DROP\n")
            f.write("COMMIT\n") 
        print(f"Generated {count} INPUT DROP rules to {filename}.")
        return True
    except Exception as e:
        print(f"ERROR: Generating iptables rules file {filename}: {e}")
        return False

def apply_iptables_rules(filename):
    print(f"Applying iptables rules from {filename} using iptables-restore...")
    
    
    cmd = ["sudo", "iptables-restore", "--noflush", filename]
    stdout, stderr = run_local_command(cmd, check=False) 
    if stderr and "Error" in stderr: 
         print(f"ERROR applying iptables rules. Stderr:\n{stderr.strip()}")
         return False 
    elif stderr:
         print(f"Warning during iptables-restore: {stderr.strip()}") 
    print("iptables rules applied (or attempted with warnings).")
    return True

def clear_all_iptables_rules():
    """Clears all rules, chains, and resets policies to ACCEPT."""
    print("Clearing all iptables rules, chains, and setting policies to ACCEPT...")
    commands = [
        ["sudo", "iptables", "-P", "INPUT", "ACCEPT"],
        ["sudo", "iptables", "-P", "FORWARD", "ACCEPT"],
        ["sudo", "iptables", "-P", "OUTPUT", "ACCEPT"],
        ["sudo", "iptables", "-t", "nat", "-F"],
        ["sudo", "iptables", "-t", "mangle", "-F"],
        ["sudo", "iptables", "-F"], 
        ["sudo", "iptables", "-X"]  
    ]
    all_ok = True
    for cmd in commands:
        stdout, stderr = run_local_command(cmd, check=False)
        if stderr:
            print(f"WARNING executing {' '.join(cmd)}: {stderr.strip()}")
            if "Error" in stderr: 
                all_ok = False
    if all_ok:
        print("iptables cleared successfully.")
    else:
        print("iptables cleared with errors/warnings.")
    return all_ok

def display_and_count_input_rules():
    """Displays first few INPUT rules and counts total rules in the chain."""
    print("--- Verifying INPUT Rules ---")
    
    cmd = ["sudo", "iptables", "-nvL", "INPUT", "--line-numbers"]
    stdout, stderr = run_local_command(cmd)

    if stdout is None:
        print("ERROR: Failed to list iptables INPUT rules.")
        return 0

    lines = stdout.strip().split('\n')
    rule_count = 0
    first_rules = []
    header_lines = 2 

    if len(lines) <= header_lines:
        print("INPUT Chain is empty or only contains headers.")
        return 0

    print(f"Header: {lines[0]}")
    print(f"Header: {lines[1]}")

    for i, line in enumerate(lines):
        if i < header_lines:
            continue 

        
        if line.strip() and line.strip().split()[0].isdigit():
            rule_count += 1
            if rule_count <= 3: 
                first_rules.append(line.strip())
        else:
             print(f"Skipping non-rule line: {line}") 

    print(f"\nActual rule count in INPUT chain: {rule_count}")
    if first_rules:
        print("First 3 rules found:")
        for rule_line in first_rules:
            print(f"  {rule_line}")
    else:
         print("No specific rules found in the chain (after headers).")

    print("--- End Verification ---")
    return rule_count


def parse_iperf_output(output):
    if not output: return 0.0
    bandwidth = 0.0
    lines = output.strip().split('\n')
    
    for line in reversed(lines):
        
        is_summary = '[SUM]' in line or 'sender' in line or 'receiver' in line
        has_rate = 'bits/sec' in line
        has_interval = 'sec' in line

        if is_summary and has_rate and has_interval:
            parts = line.split()
            unit_multiplier = 1.0
            value_index = -1
            try:
                
                for i, part in enumerate(parts):
                    part_lower = part.lower()
                    rate_found = False
                    if part_lower == "mbits/sec":
                        unit_multiplier = 1.0
                        rate_found = True
                    elif part_lower == "gbits/sec":
                        unit_multiplier = 1000.0
                        rate_found = True
                    elif part_lower == "kbits/sec":
                        unit_multiplier = 0.001
                        rate_found = True
                    elif part_lower == "bits/sec":
                         unit_multiplier = 0.000001
                         rate_found = True

                    if rate_found:
                        
                        if i > 0:
                            value_index = i - 1
                            break
                        else: 
                            value_index = -1
                            break

                if value_index >= 0 and value_index < len(parts):
                    bandwidth = float(parts[value_index]) * unit_multiplier
                    print(f"Parsed Bandwidth: {bandwidth:.2f} Mbits/sec (from line: '{line.strip()}')")
                    return bandwidth 
            except (ValueError, IndexError):
                
                print(f"Warning: Could not parse bandwidth value from line: '{line.strip()}'")
                continue
    print("WARNING: Failed to parse iperf bandwidth from output.")
    
    
    
    return 0.0

def parse_vmstat_output(output):
    cpu_samples = []
    headers = []
    us_idx = -1
    sy_idx = -1
    headers_found = False

    for line in output.strip().split('\n'):
        line = line.strip()
        if not line:
            continue

        if not headers_found:
            if 'us' in line and 'sy' in line and 'id' in line:
                headers = line.split()
                try:
                    us_idx = headers.index('us')
                    sy_idx = headers.index('sy')
                    headers_found = True
                except ValueError:
                    print("WARNING: Failed to find 'us' or 'sy' in headers")
                continue
        else:
            parts = line.split()
            if len(parts) < max(us_idx, sy_idx) + 1:
                print(f"Debug: Skipping line (not enough columns): {line}")
                continue

            try:
                us = float(parts[us_idx])
                sy = float(parts[sy_idx])
                cpu_total = us + sy
                cpu_samples.append(cpu_total)
            except (ValueError, IndexError) as e:
                print(f"WARNING: Failed to parse CPU values from line: {line} ({str(e)})")

    if not cpu_samples:
        print("WARNING: No valid CPU samples found in vmstat output")
        return 0.0

    avg_cpu = sum(cpu_samples) / len(cpu_samples)
    return round(avg_cpu, 2)

def parse_sar_mem_output(output):
    """Parses 'sar -r' output for average %memused."""
    if not output: return 0.0
    lines = output.strip().split('\n');
    mem_sum = 0.0
    count = 0
    memused_index = -1
    header_found = False

    
    for line in lines:
        parts = line.split()
        if not parts: continue
        
        if 'kbmemfree' in parts and 'kbmemused' in parts and '%memused' in parts:
            try:
                memused_index = parts.index('%memused')
                header_found = True
                print(f"Found sar header, '%memused' column index: {memused_index}")
                break 
            except ValueError:
                
                continue

    if not header_found:
        print("WARNING: Could not find '%memused' column header in sar output.")
        print("--- sar output for debugging ---")
        print(output)
        print("--- end sar output ---")
        return 0.0

    avg_mem_from_average_line = -1.0 
    for line in lines:
        parts = line.split()
        if not parts: continue
        if "Average:" in parts[0]:
            if len(parts) > memused_index:
                try:
                    avg_val = float(parts[memused_index])
                    
                    if 0 <= avg_val <= 100:
                        avg_mem_from_average_line = avg_val
                        print(f"Found Average line value for %memused: {avg_mem_from_average_line:.2f}%")
                        
                        break
                    else:
                        print(f"WARNING: Unreasonable value in Average line '%memused' column: {parts[memused_index]}")
                except (ValueError, IndexError):
                    print(f"WARNING: Could not parse float from Average line '%memused' column: {parts[memused_index]}")
            else:
                print("WARNING: Average line found, but not enough columns for %memused index.")

        if len(parts) > memused_index and ':' in parts[0] and parts[0][0].isdigit():
            try:
                mem_used_percent = float(parts[memused_index])
                if 0 <= mem_used_percent <= 100:
                    mem_sum += mem_used_percent;
                    count += 1
                    
                else:
                    print(f"Warning: Skipping unreasonable %memused value ({mem_used_percent:.2f}%) from line: {line}")
            except (ValueError, IndexError):
                
                
                continue
    if avg_mem_from_average_line >= 0:
         print(f"Using value from Average line: {avg_mem_from_average_line:.2f}%")
         return avg_mem_from_average_line
    elif count > 0:
        
        avg_mem = mem_sum / count
        print(f"Using manually calculated average: {avg_mem:.2f}% from {count} samples")
        return avg_mem
    else:
        
        print("WARNING: Failed to parse sar memory data (no valid data or Average line parsed).")
        print("--- sar output for debugging (retry) ---") 
        print(output)
        print("--- end sar output ---")
        return 0.0


def write_results_to_csv(filename, header, data_row):
    file_exists = os.path.isfile(filename)
    try:
        with open(filename, 'a', newline='') as csvfile:
            writer = csv.writer(csvfile)
            if not file_exists or os.path.getsize(filename) == 0:
                writer.writerow(header)
            writer.writerow(data_row)
    except Exception as e:
        print(f"ERROR: Writing to CSV {filename}: {e}")


if __name__ == "__main__":
    print("Starting iptables INPUT chain performance test...")

    
    required_tools = ["iptables", "iptables-restore", "vmstat", "sar", "sshpass", "iperf3", "sudo"]
    missing_tools = []
    for tool in required_tools:
        if shutil.which(tool) is None:
            missing_tools.append(tool)
    if missing_tools:
        print(f"CRITICAL ERROR: Required tools not found: {', '.join(missing_tools)}")
        if "vmstat" in missing_tools or "sar" in missing_tools:
            print("Hint: 'vmstat' and 'sar' are usually in the 'sysstat' package. Install it (e.g., 'sudo apt install sysstat').")
        if "sshpass" in missing_tools:
            print("Hint: Install 'sshpass' (e.g., 'sudo apt install sshpass').")
        exit(1)

    
    os.makedirs(RESULTS_DIR, exist_ok=True)
    print(f"Results will be saved in: {RESULTS_DIR}")

    
    for f in [FILENAME_BANDWIDTH, FILENAME_CPU, FILENAME_MEM]:
        if os.path.exists(f):
            print(f"Removing existing results file: {f}")
            try:
                os.remove(f)
            except OSError as e:
                 print(f"Warning: Could not remove {f}: {e}")

    
    if not clear_all_iptables_rules():
         print("Warning: Initial iptables clear reported errors. Continuing cautiously.")

    
    print("\n--- Starting iperf3 server on DUT ---")
    iperf_server_cmd = ["iperf3", "-s", "-B", DUT_IP]
    iperf_server_process = start_background_monitor(iperf_server_cmd)
    if not iperf_server_process:
         print("CRITICAL ERROR: Failed to start iperf3 server on DUT. Exiting.")
         exit(1)
    print("iperf3 server started. Waiting 3s...")
    time.sleep(3)

    
    for count in RULE_COUNTS:
        print(f"\n{'='*10} TESTING: iptables INPUT with {count} rules {'='*10}")
        vmstat_monitor = None 
        sar_monitor = None
        vmstat_output = None
        sar_output = None

        try:
            
            print("\n--- Step 1: Preparing iptables Rules ---")
            
            if not clear_all_iptables_rules():
                print(f"Warning: Failed to reliably clear iptables before testing {count} rules. Results might be affected.")

            if count > 0:
                if not generate_iptables_input_rules(count, IPTABLES_RULES_FILE):
                    print(f"ERROR: Failed to generate rules for count {count}. Skipping test.")
                    continue 
                if not apply_iptables_rules(IPTABLES_RULES_FILE):
                    print(f"ERROR: Failed to apply rules for count {count}. Skipping test.")
                    continue 
            else:
                print("Using default ACCEPT policy (0 rules).")

            
            actual_rules = display_and_count_input_rules()
            if count > 0 and actual_rules < count * 0.9: 
                 print(f"WARNING: Expected {count} rules, but found only {actual_rules}. Check iptables-restore output.")
                 

            print(f"Rules prepared for {count}. Waiting 5s before monitoring...")
            time.sleep(5)

            
            print("\n--- Step 2: Starting Resource Monitors (vmstat & sar) ---")
            
            num_samples = (TEST_DURATION // MONITOR_INTERVAL) + 5 

            
            vmstat_cmd = ["vmstat", str(MONITOR_INTERVAL), str(num_samples)]
            vmstat_monitor = start_background_monitor(vmstat_cmd)
            
            sar_cmd = ["sar", "-r", str(MONITOR_INTERVAL), str(num_samples)]
            sar_monitor = start_background_monitor(sar_cmd)

            if not vmstat_monitor or not sar_monitor:
                print("ERROR: Failed to start one or both resource monitors, skipping test.")
                stop_background_monitor(vmstat_monitor) 
                stop_background_monitor(sar_monitor)
                clear_all_iptables_rules() 
                continue
            print("Monitors started. Waiting 3s before traffic...")
            time.sleep(3)

            
            print("\n--- Step 3: Starting Traffic Generation ---")
            iperf_client_cmd = f"iperf3 -c {DUT_IP} -t {TEST_DURATION} -B {GENERATOR_IP} -P {IPERF_STREAMS}"
            iperf_stdout, iperf_stderr = run_remote_command(GENERATOR_IP, SSH_USER, SSH_PASSWORD, iperf_client_cmd, timeout=TEST_DURATION + 20) 
            print("--- Traffic Generation Finished ---")
            if iperf_stdout is None:
                print("ERROR: iperf3 client failed or timed out. Bandwidth results might be 0 or inaccurate.")
            
            print("\n--- Step 4: Stopping Resource Monitors ---")
            
            print(f"Waiting {MONITOR_INTERVAL}s for final monitor samples...")
            time.sleep(MONITOR_INTERVAL)

            vmstat_output, vmstat_err = stop_background_monitor(vmstat_monitor)
            sar_output, sar_err = stop_background_monitor(sar_monitor)

            
            print("\n--- Step 5: Processing and Recording Results ---")
            bandwidth_mbps = parse_iperf_output(iperf_stdout) if iperf_stdout else 0.0
            
            avg_cpu_percent = parse_vmstat_output(vmstat_output) if vmstat_output else 0.0
            avg_mem_percent = parse_sar_mem_output(sar_output) if sar_output else 0.0

            print(f"Recording results for {count} rules: BW={bandwidth_mbps:.2f} Mbps, System_CPU={avg_cpu_percent:.2f}%, System_MEM={avg_mem_percent:.2f}%")
            write_results_to_csv(FILENAME_BANDWIDTH, ["RuleCount", "Bandwidth_Mbps"], [count, f"{bandwidth_mbps:.2f}"])
            write_results_to_csv(FILENAME_CPU, ["RuleCount", "Avg_System_CPU_Percent_NonIdle"], [count, f"{avg_cpu_percent:.2f}"])
            write_results_to_csv(FILENAME_MEM, ["RuleCount", "Avg_System_MEM_Used_Percent"], [count, f"{avg_mem_percent:.2f}"])

        except Exception as e:
            print(f"\n!!! UNEXPECTED ERROR during test for {count} rules: {e} !!!")
            import traceback
            traceback.print_exc()
            
            if vmstat_monitor and vmstat_monitor.poll() is None:
                 stop_background_monitor(vmstat_monitor)
            if sar_monitor and sar_monitor.poll() is None:
                 stop_background_monitor(sar_monitor)

        finally:
            print(f"--- Test for {count} rules completed ---")
            print("Waiting 5s before next rule count...")
            time.sleep(5)

    
    print("\n" + "="*10 + " Final Cleanup " + "="*10)
    clear_all_iptables_rules() 
    stop_background_monitor(iperf_server_process) 
    
    if os.path.exists(IPTABLES_RULES_FILE):
        print(f"Removing temporary rules file {IPTABLES_RULES_FILE}")
        try:
             os.remove(IPTABLES_RULES_FILE)
        except Exception as e:
             print(f"WARNING: Failed to remove temporary rules file: {e}")

    print("\niptables INPUT chain performance testing finished.")
    print(f"Results saved in directory: {RESULTS_DIR}")