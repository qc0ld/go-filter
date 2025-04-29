import subprocess
import time
import csv
import os
import signal
import random
import ipaddress
from datetime import datetime
import shutil 
import psycopg2 
from psycopg2 import sql 


GENERATOR_IP = "192.168.188.183"    
DUT_IP = "192.168.188.182"          
SSH_USER = "kali"                   
SSH_PASSWORD = "kali"               
TEST_DURATION = 10                  
MONITOR_INTERVAL = 2                

RULE_COUNTS = list(range(0, 50001, 1000))
IPERF_STREAMS = 4                   


DB_HOST = "127.0.0.1"               
DB_PORT = "5432"                    
DB_USER = "postgres"                
DB_PASSWORD = "postgres"            
DB_NAME = "blocked_ip_db"           
DB_TABLE = "blocked_ips"            


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

def get_db_connection():
    try:
        conn = psycopg2.connect(
            dbname=DB_NAME,
            user=DB_USER,
            password=DB_PASSWORD,
            host=DB_HOST,
            port=DB_PORT
        )
        return conn
    except psycopg2.OperationalError as e:
        print(f"CRITICAL ERROR: Failed to connect to database '{DB_NAME}' on {DB_HOST}:{DB_PORT}. Error: {e}")
        print("Hint: Check DB server status, connection parameters, firewall, and pg_hba.conf.")
        return None
    except Exception as e:
        print(f"CRITICAL ERROR: Unexpected error connecting to database: {e}")
        return None

def clear_blocked_ips():
    print(f"Clearing table '{DB_TABLE}' in database '{DB_NAME}'...")
    conn = get_db_connection()
    if not conn:
        return False
    try:
        with conn.cursor() as cur:
            query = sql.SQL("DELETE FROM {};").format(sql.Identifier(DB_TABLE))
            cur.execute(query)
        conn.commit()
        print(f"Table '{DB_TABLE}' cleared successfully.")
        return True
    except Exception as e:
        print(f"ERROR: Failed to clear table '{DB_TABLE}': {e}")
        conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def generate_random_ip():
    while True:
        try:
             first_octet = random.choice([random.randint(1, 9), random.randint(11, 126), random.randint(128, 168), random.randint(173, 191), random.randint(193, 223)])
             ip_str = f"{first_octet}.{random.randint(0, 255)}.{random.randint(0, 255)}.{random.randint(1, 254)}"
             ip = ipaddress.ip_address(ip_str)
             if not ip.is_private and not ip.is_loopback and not ip.is_multicast and not ip.is_link_local:
                 return ip_str
        except ValueError:
             continue

def add_blocked_ips(count):
    if count <= 0:
        print("No IPs to add.")
        return True

    print(f"Generating and adding {count} unique random IPs to table '{DB_TABLE}'...")
    ips_to_add = set()
    while len(ips_to_add) < count:
        ips_to_add.add(generate_random_ip())

    conn = get_db_connection()
    if not conn:
        return False

    start_time = time.time()
    try:
        with conn.cursor() as cur:
            from psycopg2.extras import execute_values
            ip_tuples = [(ip,) for ip in ips_to_add]
            query = sql.SQL("INSERT INTO {} (ip) VALUES %s ON CONFLICT (ip) DO NOTHING;").format(sql.Identifier(DB_TABLE))
            execute_values(cur, query.as_string(conn), ip_tuples)

        conn.commit()
        duration = time.time() - start_time
        print(f"Successfully added {len(ips_to_add)} unique IPs to '{DB_TABLE}' in {duration:.2f} seconds.")
        time.sleep(1)
        return True
    except Exception as e:
        print(f"ERROR: Failed to add IPs to table '{DB_TABLE}': {e}")
        conn.rollback()
        return False
    finally:
        if conn:
            conn.close()

def count_blocked_ips():
    print(f"Counting IPs in table '{DB_TABLE}'...")
    conn = get_db_connection()
    if not conn:
        return -1
    count = -1
    try:
        with conn.cursor() as cur:
            query = sql.SQL("SELECT COUNT(*) FROM {};").format(sql.Identifier(DB_TABLE))
            cur.execute(query)
            result = cur.fetchone()
            if result:
                count = result[0]
                print(f"Found {count} IPs in '{DB_TABLE}'.")
    except Exception as e:
        print(f"ERROR: Failed to count IPs in table '{DB_TABLE}': {e}")
        count = -1
    finally:
        if conn:
            conn.close()
    return count

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
                        unit_multiplier = 1.0; rate_found = True
                    elif part_lower == "gbits/sec":
                        unit_multiplier = 1000.0; rate_found = True
                    elif part_lower == "kbits/sec":
                        unit_multiplier = 0.001; rate_found = True
                    elif part_lower == "bits/sec":
                         unit_multiplier = 0.000001; rate_found = True
                    if rate_found:
                        if i > 0: value_index = i - 1; break
                        else: value_index = -1; break
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
    if not output: return 0.0
    lines = output.strip().split('\n')
    cpu_sum = 0.0
    count = 0
    header_line1_found = False
    header_line2_found = False
    idle_col_index = -1
    data_processing_started = False
    
    for i, line in enumerate(lines):
        parts = line.split()
        line_strip = line.strip()
        if not parts: continue
        
        if not header_line1_found:
            if "procs" in line_strip and "memory" in line_strip and "cpu" in line_strip:
                header_line1_found = True
                
                continue
        elif header_line1_found and not header_line2_found:
            
            if 'us' in parts and 'sy' in parts and 'id' in parts:
                try:
                    idle_col_index = parts.index('id')
                    header_line2_found = True
                    
                    continue
                except ValueError:
                    
                    header_line1_found = False
                    continue
            else:
                 
                 pass
        if header_line1_found and header_line2_found and idle_col_index != -1:
            is_header_line_2 = 'us' in parts and 'sy' in parts and 'id' in parts
            if not is_header_line_2:
                 if not data_processing_started:
                      
                      data_processing_started = True
                 
                 if len(parts) > idle_col_index:
                     if parts[0].isdigit():
                         
                         try:
                             idle_cpu_str = parts[idle_col_index]
                             idle_cpu = float(idle_cpu_str)
                             non_idle_cpu = 100.0 - idle_cpu
                             if 0 <= non_idle_cpu <= 100:
                                 cpu_sum += non_idle_cpu
                                 count += 1
                                 
                             
                         except (ValueError, IndexError) as parse_error:
                             
                             continue
    if count > 0:
        avg_cpu = cpu_sum / count
        print(f"Parsed Avg System CPU (non-idle): {avg_cpu:.2f}% from {count} vmstat samples")
        return avg_cpu
    else:
        print("WARNING: Failed to parse vmstat CPU data (no valid samples found or headers incorrect).")
        print("--- vmstat output for debugging ---"); print(output); print("--- end vmstat output ---")
        return 0.0

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
                
                break
            except ValueError: continue
    if not header_found:
        print("WARNING: Could not find '%memused' column header in sar output.")
        print("--- sar output for debugging ---"); print(output); print("--- end sar output ---")
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
                        
                        break
                    
                except (ValueError, IndexError): continue 
            
        if len(parts) > memused_index and ':' in parts[0] and parts[0][0].isdigit():
            try:
                mem_used_percent = float(parts[memused_index])
                if 0 <= mem_used_percent <= 100:
                    mem_sum += mem_used_percent; count += 1
                
            except (ValueError, IndexError): continue
    if avg_mem_from_average_line >= 0:
         print(f"Using value from Average line: {avg_mem_from_average_line:.2f}%")
         return avg_mem_from_average_line
    elif count > 0:
        avg_mem = mem_sum / count
        print(f"Using manually calculated average: {avg_mem:.2f}% from {count} samples")
        return avg_mem
    else:
        print("WARNING: Failed to parse sar memory data (no valid data or Average line parsed).")
        print("--- sar output for debugging (retry) ---"); print(output); print("--- end sar output ---")
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

    filter_choice = -1
    filter_name = "Unknown"
    base_results_dir = ""

    while filter_choice not in [0, 1]:
        print("\n Which filter is testing?")
        print("  0: Go Filter")
        print("  1: XDP Filter")
        choice_str = input("  Enter:> ")
        try:
            filter_choice = int(choice_str)
            if filter_choice == 0:
                filter_name = "gofilter"
                base_results_dir = "./results/gofilter"
            elif filter_choice == 1:
                filter_name = "xdpfilter"
                base_results_dir = "./results/xdpfilter"
            else:
                print("Choose 0 or 1")
        except ValueError:
            print("Incorrect input. Choose 0 or 1")

    print(f"\nTesting: {filter_name}")

    RESULTS_DIR = base_results_dir
    FILENAME_BANDWIDTH = os.path.join(RESULTS_DIR, f"bandwidth_vs_{filter_name.lower()}_ips.csv")
    FILENAME_CPU = os.path.join(RESULTS_DIR, f"system_cpu_vs_{filter_name.lower()}_ips.csv")
    FILENAME_MEM = os.path.join(RESULTS_DIR, f"system_mem_vs_{filter_name.lower()}_ips.csv")

    required_tools = ["vmstat", "sar", "sshpass", "iperf3", "sudo"]
    missing_tools = []
    try:
        import psycopg2
    except ImportError:
        missing_tools.append("psycopg2 (Python package)")
    for tool in required_tools:
        if shutil.which(tool) is None:
            missing_tools.append(tool)
    if missing_tools:
        print(f"CRITICAL ERROR: Required tools/packages not found: {', '.join(missing_tools)}")
        if "psycopg2 (Python package)" in missing_tools: print("Hint: Install psycopg2 using 'pip install psycopg2-binary'.")
        if "vmstat" in missing_tools or "sar" in missing_tools: print("Hint: 'vmstat' and 'sar' in 'sysstat' package.")
        if "sshpass" in missing_tools: print("Hint: Install 'sshpass'.")
        exit(1)

    os.makedirs(RESULTS_DIR, exist_ok=True)
    print(f"Results will be saved in: {RESULTS_DIR}")

    
    for f in [FILENAME_BANDWIDTH, FILENAME_CPU, FILENAME_MEM]:
        if os.path.exists(f):
            print(f"Removing existing results file: {f}")
            try: os.remove(f)
            except OSError as e: print(f"Warning: Could not remove {f}: {e}")

    
    print("\n--- Initial Database Cleanup ---")
    if not clear_blocked_ips():
        print("CRITICAL ERROR: Failed initial database cleanup. Exiting.")
        exit(1)
    
    print("\n--- Starting iperf3 server on DUT ---")
    iperf_server_cmd = ["iperf3", "-s", "-B", DUT_IP]
    iperf_server_process = start_background_monitor(iperf_server_cmd)
    if not iperf_server_process:
        print("CRITICAL ERROR: Failed to start iperf3 server. Exiting.")
        clear_blocked_ips()
        exit(1)
    print("iperf3 server started. Waiting 2...")
    time.sleep(2)

    for count in RULE_COUNTS:
        print(f"\n{'='*10} TESTING: {filter_name} with {count} IPs in DB {'='*10}")
        vmstat_monitor = None
        sar_monitor = None
        vmstat_output = None
        sar_output = None
        
        print("\n--- Step 1: Preparing Database ---")
        if not clear_blocked_ips():
            print(f"ERROR: Failed to clear database for count {count}. Skipping test.")
            continue
        if count > 0:
            if not add_blocked_ips(count):
                print(f"ERROR: Failed to add {count} IPs to database. Skipping test.")
                continue
        else:
            print("Using empty database (0 IPs).")

        actual_ips_in_db = count_blocked_ips()
        if actual_ips_in_db != count:
            print(f"WARNING: Expected {count} IPs in DB, but found {actual_ips_in_db}.")

        print(f"Database prepared with {actual_ips_in_db} IPs. Waiting 2s before monitoring...")
        time.sleep(2)

        try:
            
            print("\n--- Step 2: Starting Resource Monitors (vmstat & sar) ---")
            num_samples = (TEST_DURATION // MONITOR_INTERVAL) + 5
            vmstat_cmd = ["vmstat", str(MONITOR_INTERVAL), str(num_samples)]
            sar_cmd = ["sar", "-r", str(MONITOR_INTERVAL), str(num_samples)]
            vmstat_monitor = start_background_monitor(vmstat_cmd)
            sar_monitor = start_background_monitor(sar_cmd)
            if not vmstat_monitor or not sar_monitor:
                 print("ERROR: Failed to start one or both system monitors, skipping test.")
                 stop_background_monitor(vmstat_monitor)
                 stop_background_monitor(sar_monitor)
                 continue

            print(f"System monitors (vmstat, sar) started. Waiting 2s before traffic...")
            time.sleep(2)
            
            print("\n--- Step 3: Starting Traffic Generation (iperf3 client) ---")
            iperf_client_cmd = f"iperf3 -c {DUT_IP} -t {TEST_DURATION} -B {GENERATOR_IP} -P {IPERF_STREAMS}"
            iperf_stdout, iperf_stderr = run_remote_command(GENERATOR_IP, SSH_USER, SSH_PASSWORD, iperf_client_cmd, timeout=TEST_DURATION + 20)
            print("--- Traffic Generation Finished ---")
            if iperf_stdout is None:
                print("ERROR: iperf3 client failed or timed out.")
            
            print("\n--- Step 4: Stopping Resource Monitors ---")
            print(f"Waiting {MONITOR_INTERVAL}s for final monitor samples...")
            time.sleep(MONITOR_INTERVAL)
            vmstat_output, vmstat_err = stop_background_monitor(vmstat_monitor)
            sar_output, sar_err = stop_background_monitor(sar_monitor)

            
            print("\n--- Step 5: Processing and Recording Results ---")
            bandwidth_mbps = parse_iperf_output(iperf_stdout) if iperf_stdout else 0.0
            avg_system_cpu_percent = parse_vmstat_output(vmstat_output) if vmstat_output else 0.0
            avg_system_mem_percent = parse_sar_mem_output(sar_output) if sar_output else 0.0

            print(f"Recording results for {count} IPs ({filter_name}): BW={bandwidth_mbps:.2f} Mbps, System_CPU={avg_system_cpu_percent:.2f}%, System_MEM={avg_system_mem_percent:.2f}%")
            
            write_results_to_csv(FILENAME_BANDWIDTH, ["RuleCount", "Bandwidth_Mbps"], [count, f"{bandwidth_mbps:.2f}"])
            write_results_to_csv(FILENAME_CPU, ["RuleCount", "Avg_System_CPU_Percent_NonIdle"], [count, f"{avg_system_cpu_percent:.2f}"])
            write_results_to_csv(FILENAME_MEM, ["RuleCount", "Avg_System_MEM_Used_Percent"], [count, f"{avg_system_mem_percent:.2f}"])

        except Exception as e:
            print(f"\n!!! UNEXPECTED ERROR during test for {count} IPs ({filter_name}): {e} !!!")
            import traceback
            traceback.print_exc()
            if vmstat_monitor and vmstat_monitor.poll() is None: stop_background_monitor(vmstat_monitor)
            if sar_monitor and sar_monitor.poll() is None: stop_background_monitor(sar_monitor)

        finally:
            
            print(f"--- Test for {count} IPs ({filter_name}) completed ---")
            print("Waiting 3s before next rule count...")
            time.sleep(3)
    
    print("\n" + "="*10 + " Final Cleanup " + "="*10)
    print("Final database cleanup...")
    clear_blocked_ips()
    print("Stopping iperf3 server...")
    stop_background_monitor(iperf_server_process)

    print(f"\nPerformance testing for {filter_name} finished.")
    print(f"Results saved in directory: {RESULTS_DIR}")
    print(f"*** Remember to stop the {filter_name} application if it's still running! ***")
