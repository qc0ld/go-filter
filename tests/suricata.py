import subprocess
import time
import csv
import os
import signal
import random
import ipaddress
from datetime import datetime
import yaml 
import shutil 


GENERATOR_IP = "192.168.188.183"    
DUT_IP = "192.168.188.182"          
SSH_USER = "kali"                   
SSH_PASSWORD = "kali"               
TEST_DURATION = 10
MONITOR_INTERVAL = 2
RULE_COUNTS = list(range(0, 50001, 1000))
DUT_INTERFACE = "eth0"
SURICATA_CONFIG_FILE = "/etc/suricata/suricata.yaml"
TEMP_RULES_DIR = "/tmp/suricata_test_rules"
TEMP_GENERATED_RULE_FILENAME = "generated_drop_rules.rules"
TEMP_CONFIG_FILE = "/tmp/suricata_test_config.yaml"
SID_START = 2000001
SURICATA_PROCESS_NAME = "Suricata-Main"
IPERF_STREAMS = 4

RESULTS_DIR = "./results/suricata"

FILENAME_BANDWIDTH = os.path.join(RESULTS_DIR, "bandwidth_vs_suricata_rules.csv")
FILENAME_CPU = os.path.join(RESULTS_DIR, "system_cpu_vs_suricata_rules.csv")
FILENAME_MEM = os.path.join(RESULTS_DIR, "system_mem_vs_suricata_rules.csv")

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

def generate_suricata_drop_rules(count, filename, start_sid):
    print(f"Generating {count} Suricata drop rules to {filename} (starting SID: {start_sid})...")
    current_sid = start_sid
    try:
        with open(filename, "w") as f:
            for i in range(count):
                random_ip_src = generate_random_ip()
                rule = f'drop ip {random_ip_src} any -> any any (msg:"Generated Drop Rule {i+1} for src {random_ip_src}"; sid:{current_sid}; rev:1;)\n'
                f.write(rule)
                current_sid += 1
        print(f"Generated {count} Suricata drop rules to {filename}. Last SID: {current_sid - 1}")
        return filename
    except Exception as e:
        print(f"ERROR: Generating Suricata rules file {filename}: {e}")
        return None

def create_suricata_test_config(base_config_path, temp_config_path, generated_rule_filename, rule_dir, interface):
    print(f"Creating temporary Suricata config {temp_config_path} based on {base_config_path}")
    if not os.path.exists(base_config_path):
        print(f"CRITICAL ERROR: Base Suricata config not found: {base_config_path}"); return False

    try:
        with open(base_config_path, 'r') as f_base:
            config_data = yaml.safe_load(f_base)
        if not config_data:
            print(f"ERROR: Failed to parse base config YAML: {base_config_path}"); return False

        config_data['rule-files'] = [ generated_rule_filename ]
        config_data['default-rule-path'] = rule_dir
        print(f"Set rule-files to: [{generated_rule_filename}] in rule dir: {rule_dir}")

        af_packet_found_and_set = False
        if 'af-packet' in config_data and isinstance(config_data['af-packet'], list):
             for i, iface_conf in enumerate(config_data['af-packet']):
                  if isinstance(iface_conf, dict) and 'interface' in iface_conf:
                      config_data['af-packet'][i]['interface'] = interface
                      config_data['af-packet'] = [config_data['af-packet'][i]]
                      af_packet_found_and_set = True
                      print(f"Modified existing af-packet section to use interface: {interface}")
                      break
        if not af_packet_found_and_set:
             print(f"WARNING: 'af-packet' section not found or misconfigured in base config. Adding default entry for interface {interface}.")
             config_data['af-packet'] = [{'interface': interface, 'threads': 'auto', 'cluster-type': 'cluster_flow', 'cluster-id': 99}]

        if 'outputs' in config_data and isinstance(config_data['outputs'], list):
             for output_cfg in config_data.get('outputs', []):
                 if isinstance(output_cfg, dict):
                     for key in output_cfg:
                         if isinstance(output_cfg[key], dict) and 'enabled' in output_cfg[key]:
                             output_cfg[key]['enabled'] = 'no'
             print("Disabled default logging outputs in temporary config for performance test.")
        else:
            print("WARNING: 'outputs' section not found in base config. Cannot disable default logs.")

        with open(temp_config_path, 'w') as f_temp:
            f_temp.write("%YAML 1.1\n")
            f_temp.write("---\n")
            yaml.dump(config_data, f_temp, default_flow_style=False, sort_keys=False, width=1000)

        print(f"Temporary Suricata config saved successfully to: {temp_config_path}")
        return True

    except yaml.YAMLError as e:
        print(f"ERROR: Parsing YAML config {base_config_path}: {e}"); return False
    except Exception as e:
        print(f"ERROR: Creating temporary Suricata config {temp_config_path}: {e}"); return False

def stop_suricata_instance():
    print("Stopping any running Suricata instances (excluding this script)...")
    script_pid = os.getpid()
    print(f"Current script PID: {script_pid}")

    print(f"Attempting gentle stop using 'pkill -x {SURICATA_PROCESS_NAME}'...")
    cmd_pkill_main = ["sudo", "pkill", "-x", SURICATA_PROCESS_NAME]
    run_local_command(cmd_pkill_main, check=False)
    time.sleep(1)

    print(f"Finding potential remaining Suricata processes using 'pgrep -x {SURICATA_PROCESS_NAME}'...")
    pgrep_cmd = ["pgrep", "-x", SURICATA_PROCESS_NAME]
    stdout_pgrep, stderr_pgrep = run_local_command(pgrep_cmd, check=False)

    if stdout_pgrep and stdout_pgrep.strip():
        pids_found = stdout_pgrep.strip().split()
        pids_to_kill = []
        print(f"Found PIDs matching '{SURICATA_PROCESS_NAME}': {', '.join(pids_found)}")

        for pid_str in pids_found:
            try:
                pid = int(pid_str)
                if pid == script_pid:
                    print(f"Skipping script's own PID: {pid}")
                    continue
                pids_to_kill.append(str(pid))
            except ValueError:
                print(f"Warning: Found non-integer PID '{pid_str}' in pgrep output.")
                continue

        if pids_to_kill:
            print(f"Attempting SIGTERM for {SURICATA_PROCESS_NAME} PIDs: {', '.join(pids_to_kill)}")
            cmd_kill_term = ["sudo", "kill", "-TERM"] + pids_to_kill
            run_local_command(cmd_kill_term, check=False)
            time.sleep(2)

            remaining_pids = []
            for pid in pids_to_kill:
                 stdout_check, _ = run_local_command(["ps", "-p", pid], check=False)
                 if stdout_check and len(stdout_check.strip().split('\n')) > 1:
                     remaining_pids.append(pid)

            if remaining_pids:
                print(f"Attempting SIGKILL for remaining {SURICATA_PROCESS_NAME} PIDs: {', '.join(remaining_pids)}")
                cmd_kill_kill = ["sudo", "kill", "-KILL"] + remaining_pids
                run_local_command(cmd_kill_kill, check=False)
                time.sleep(1)
        else:
            print(f"No other '{SURICATA_PROCESS_NAME}' PIDs found to kill.")

    else:
        print(f"No processes found matching '{SURICATA_PROCESS_NAME}' via pgrep.")
    return True

def start_suricata_with_config(config_file, interface):
    print(f"Starting Suricata with config {config_file} on interface {interface}...")
    cmd = ["sudo", "suricata", "-c", config_file, "-i", interface, "-D"]
    stdout, stderr = run_local_command(cmd, check=False)

    if stderr and ("Error" in stderr or "ERROR" in stderr):
        print(f"ERROR: Starting Suricata failed. Stderr:\n{stderr.strip()}")
        print("Check Suricata logs (e.g., /var/log/suricata/suricata.log) for details.")
        return False 

    print("Waiting 7s for Suricata process to initialize and stabilize...")
    time.sleep(7)

    
    pgrep_cmd = ["pgrep", "-x", SURICATA_PROCESS_NAME]
    print(f"Checking for Suricata process PID using: {' '.join(pgrep_cmd)}")
    stdout_check, stderr_check = run_local_command(pgrep_cmd, check=False)

    if stdout_check and stdout_check.strip():
        pids = stdout_check.strip().split()
        print(f"Suricata started successfully. Found PID(s): {', '.join(pids)}.")
        return True 
    else:
        print(f"ERROR: Suricata process ({SURICATA_PROCESS_NAME}) not found after start attempt.")
        print(f"Stderr from pgrep: {stderr_check.strip()}")
        print("Check Suricata logs (e.g., /var/log/suricata/suricata.log) for startup errors.")
        
        stdout_any, _ = run_local_command(["pgrep", "-f", "suricata"], check=False)
        if stdout_any and stdout_any.strip():
            print(f"WARNING: Found other Suricata processes, but not '{SURICATA_PROCESS_NAME}'. PIDs: {stdout_any.strip()}")
        return False 

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
    print("Starting Suricata performance test (using SYSTEM-WIDE metrics)...")
    required_tools = ["suricata", "sshpass", "iperf3", "vmstat", "sar", "pgrep", "pkill", "sudo"]
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

    if not os.path.exists(SURICATA_CONFIG_FILE):
        print(f"CRITICAL ERROR: Base Suricata config not found: {SURICATA_CONFIG_FILE}"); exit(1)
    
    os.makedirs(RESULTS_DIR, exist_ok=True)
    os.makedirs(TEMP_RULES_DIR, exist_ok=True)
    print(f"Results will be saved in: {RESULTS_DIR}")
    print(f"Temporary rule file dir: {TEMP_RULES_DIR}")
    print(f"Temporary config file: {TEMP_CONFIG_FILE}")

    
    for f in [FILENAME_BANDWIDTH, FILENAME_CPU, FILENAME_MEM]:
        if os.path.exists(f):
            print(f"Removing existing results file: {f}")
            try:
                os.remove(f)
            except OSError as e:
                 print(f"Warning: Could not remove {f}: {e}")
    
    if not stop_suricata_instance():
        print("Warning: Could not reliably stop existing Suricata instances. Continuing anyway...")
    
    print("\n--- Starting iperf3 server on DUT ---")
    iperf_server_cmd = ["iperf3", "-s", "-B", DUT_IP]
    iperf_server_process = start_background_monitor(iperf_server_cmd)
    if not iperf_server_process:
        print("CRITICAL ERROR: Failed to start iperf3 server. Exiting.")
        exit(1)
    print("iperf3 server started. Waiting 3s...")
    time.sleep(3)
    
    for count in RULE_COUNTS:
        print(f"\n{'='*10} TESTING: Suricata with {count} rules (System Metrics) {'='*10}")
        suricata_started_successfully = False
        
        vmstat_monitor = None 
        sar_monitor = None    
        temp_rule_file_path = os.path.join(TEMP_RULES_DIR, TEMP_GENERATED_RULE_FILENAME)
        vmstat_output = None
        sar_output = None

        try:
            print("\n--- Step 1: Generating Rules and Configuration ---")
            stop_suricata_instance() 

            if not generate_suricata_drop_rules(count, temp_rule_file_path, SID_START):
                print(f"ERROR: Failed to generate rules for count {count}. Skipping test.")
                continue

            if not create_suricata_test_config(SURICATA_CONFIG_FILE, TEMP_CONFIG_FILE, TEMP_GENERATED_RULE_FILENAME, TEMP_RULES_DIR, DUT_INTERFACE):
                print(f"ERROR: Failed to create test config for count {count}. Skipping test.")
                continue

            print("\n--- Step 2: Starting Suricata ---")
            suricata_started_successfully = start_suricata_with_config(TEMP_CONFIG_FILE, DUT_INTERFACE)
            if not suricata_started_successfully:
                 print(f"ERROR: Failed to start Suricata for count {count}. Skipping test.")
                 continue
            else:
                 print(f"Suricata service started successfully for {count} rules.")
                 time.sleep(3) 

            print("\n--- Step 3: Starting Resource Monitors (vmstat & sar) ---")
            
            num_samples = (TEST_DURATION // MONITOR_INTERVAL) + 5

            vmstat_cmd = ["vmstat", str(MONITOR_INTERVAL), str(num_samples)]
            sar_cmd = ["sar", "-r", str(MONITOR_INTERVAL), str(num_samples)]

            vmstat_monitor = start_background_monitor(vmstat_cmd)
            sar_monitor = start_background_monitor(sar_cmd)

            if not vmstat_monitor or not sar_monitor:
                 print("ERROR: Failed to start one or both system monitors, skipping test.")
                 stop_background_monitor(vmstat_monitor)
                 stop_background_monitor(sar_monitor)
                 stop_suricata_instance() 
                 continue
            print(f"System monitors (vmstat, sar) started. Waiting 3s before traffic...")
            time.sleep(3)
            
            print("\n--- Step 4: Starting Traffic Generation (iperf3 client) ---")
            iperf_client_cmd = f"iperf3 -c {DUT_IP} -t {TEST_DURATION} -B {GENERATOR_IP} -P {IPERF_STREAMS}"
            iperf_stdout, iperf_stderr = run_remote_command(GENERATOR_IP, SSH_USER, SSH_PASSWORD, iperf_client_cmd, timeout=TEST_DURATION + 20)
            print("--- Traffic Generation Finished ---")
            if iperf_stdout is None:
                print("ERROR: iperf3 client failed or timed out. Bandwidth results might be 0 or inaccurate.")
            
            print("\n--- Step 5: Stopping Resource Monitors (vmstat & sar) ---")
            print(f"Waiting {MONITOR_INTERVAL}s for final monitor samples...")
            time.sleep(MONITOR_INTERVAL)

            vmstat_output, vmstat_err = stop_background_monitor(vmstat_monitor)
            sar_output, sar_err = stop_background_monitor(sar_monitor)
            
            print("\n--- Step 6: Processing and Recording Results ---")
            bandwidth_mbps = parse_iperf_output(iperf_stdout) if iperf_stdout else 0.0
            
            avg_system_cpu_percent = parse_vmstat_output(vmstat_output) if vmstat_output else 0.0
            avg_system_mem_percent = parse_sar_mem_output(sar_output) if sar_output else 0.0

            print(f"Recording results for {count} rules: BW={bandwidth_mbps:.2f} Mbps, System_CPU={avg_system_cpu_percent:.2f}%, System_MEM={avg_system_mem_percent:.2f}%")
            
            write_results_to_csv(FILENAME_BANDWIDTH, ["RuleCount", "Bandwidth_Mbps"], [count, f"{bandwidth_mbps:.2f}"])
            write_results_to_csv(FILENAME_CPU, ["RuleCount", "Avg_System_CPU_Percent_NonIdle"], [count, f"{avg_system_cpu_percent:.2f}"])
            write_results_to_csv(FILENAME_MEM, ["RuleCount", "Avg_System_MEM_Used_Percent"], [count, f"{avg_system_mem_percent:.2f}"])

        except Exception as e:
            print(f"\n!!! UNEXPECTED ERROR during test for {count} rules: {e} !!!")
            import traceback
            traceback.print_exc()
            
            if vmstat_monitor and vmstat_monitor.poll() is None:
                 stop_background_monitor(vmstat_monitor)
            if sar_monitor and sar_monitor.poll() is None:
                 stop_background_monitor(sar_monitor)

        finally:
            print("\n--- Step 7: Stopping Suricata and Cleaning up ---")
            if suricata_started_successfully:
                stop_suricata_instance()
            else:
                print("Skipping Suricata stop (was not started successfully).")
            
            if os.path.exists(temp_rule_file_path):
                print(f"Removing temporary rule file: {temp_rule_file_path}")
                try: os.remove(temp_rule_file_path)
                except Exception as e: print(f"WARNING: Failed to remove {temp_rule_file_path}: {e}")
            if os.path.exists(TEMP_CONFIG_FILE):
                print(f"Removing temporary config file: {TEMP_CONFIG_FILE}")
                try: os.remove(TEMP_CONFIG_FILE)
                except Exception as e: print(f"WARNING: Failed to remove {TEMP_CONFIG_FILE}: {e}")

            print(f"--- Test for {count} rules completed ---")
            print("Waiting 5s before next rule count...")
            time.sleep(5)
    
    print("\n" + "="*10 + " Final Cleanup " + "="*10)
    stop_suricata_instance() 
    stop_background_monitor(iperf_server_process) 
    
    if os.path.exists(TEMP_RULES_DIR):
        print(f"Removing temporary rules directory: {TEMP_RULES_DIR}")
        try:
            shutil.rmtree(TEMP_RULES_DIR)
        except Exception as e:
            print(f"WARNING: Failed to remove directory {TEMP_RULES_DIR}: {e}")
    
    if os.path.exists(TEMP_CONFIG_FILE):
        try:
            os.remove(TEMP_CONFIG_FILE)
        except Exception as e:
            print(f"WARNING: Failed to remove final temp config {TEMP_CONFIG_FILE}: {e}")

    print("\nSuricata performance testing (System Metrics) finished.")
    print(f"Results saved in directory: {RESULTS_DIR}")