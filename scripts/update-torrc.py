from collections import Counter
import subprocess

with open('../database/data/all-nodes.txt', 'r') as file:
    all_nodes = file.read().splitlines()

with open('../database/data/exit-nodes.txt', 'r') as file:
    exit_nodes = file.read().splitlines()

#ip_addresses = all_nodes + exit_nodes
ip_addresses = exit_nodes
ip_counts = Counter(ip_addresses)

most_common_ips = ip_counts.most_common(300)

exclude_nodes_lines = [f"ExcludeNodes {ip}" for ip, _ in most_common_ips]

with open('/etc/tor/torrc', 'r') as torrc_file:
    lines = torrc_file.readlines()

lines = [line for line in lines if not line.startswith("ExcludeNodes")]

with open('/etc/tor/torrc', 'w') as torrc_file:
    torrc_file.writelines(lines)
    torrc_file.write('\n'.join(exclude_nodes_lines) + '\n')

most_common_ip = most_common_ips[0] 
least_common_ip = most_common_ips[-1]

print(f"Most common IP: {most_common_ip[0]} with {most_common_ip[1]} occurrences.")
print(f"Least common IP: {least_common_ip[0]} with {least_common_ip[1]} occurrences.")

result = subprocess.run(['grep', '-c', '^ExcludeNodes', '/etc/tor/torrc'], stdout=subprocess.PIPE, stderr=subprocess.PIPE)

print(f"Strings number: {result.stdout.decode().strip()}")
command = ["sudo", "systemctl", "restart", "tor"]
result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
