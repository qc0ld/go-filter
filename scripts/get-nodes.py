import subprocess
import time
from stem import CircStatus
from stem.control import Controller

EXIT_NODES_FILE = "../database/data/exit-nodes.txt"
ALL_NODES_FILE = "../database/data/all-nodes.txt"
BAD_EXIT_NODES_FILE = "../database/data/bad-exit-nodes.txt"
TOR_CONFIG_FILE = "/etc/tor/torrc"

def add_node_to_file(ip_address, exit_node):
    try:
        if (exit_node == 1):
            with open(EXIT_NODES_FILE, "a") as exit_nodes_file:
                exit_nodes_file.write("{}\n".format(ip_address))
        elif (exit_node == 2):
            with open(BAD_EXIT_NODES_FILE, "a") as exit_nodes_file:
                exit_nodes_file.write("{}\n".format(ip_address))
        else:
            with open(ALL_NODES_FILE, "a") as all_nodes_file:
                all_nodes_file.write("{}\n".format(ip_address))

        print(f"IP address {ip_address} has been processed")
    except Exception as e:
        print(f"Error blocking IP: {e}")

def is_exit_node(router):
    if 'Exit' in router.flags:
        return 1
    elif 'BadExit' in router.flags:
        return 2
    else:
        return 3

def main():
    command = ["sudo", "systemctl", "restart", "tor"]
    while True:
        try:
            with Controller.from_port(port=9051) as controller:
                controller.authenticate()
                circuits = controller.get_circuits()
                for circ in controller.get_circuits():
                    print(f"Circuit ID: {circ.id}")
                    time.sleep(1)
                    for circ_hop in circ.path:
                        router = controller.get_network_status(circ_hop[0])
                        
                        print(router.flags)
                        
                        print(f"Node IP: {router.address}")

                        exit_node = is_exit_node(router)
                        
                        add_node_to_file(router.address, exit_node)

            try:
                result = subprocess.run(command, check=True, capture_output=True, text=True)
                print("Tor restarted successfully.")
            except subprocess.CalledProcessError as e:
                print("Error restarting Tor.")

            time.sleep(20)
    
        except Exception as e:
            print(f"An error occurred: {e}")
            time.sleep(5)

if __name__ == "__main__":
    main()
             
