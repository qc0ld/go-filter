def check_duplicates(file_path):
    try:
        with open(file_path, 'r') as file:
            lines = file.readlines()

        lines = [line.strip() for line in lines]

        ip_count = {}

        for line in lines:
            if line in ip_count:
                ip_count[line] += 1
            else:
                ip_count[line] = 1

        unique_ips = 0
        non_unique_ips = 0

        for count in ip_count.values():
            if count == 1:
                unique_ips += 1
            elif count > 1:
                unique_ips += 1
                non_unique_ips += count - 1

        print(f"File: {file_path}")
        print(f"Amount of unique IP addresses: {unique_ips}")
        print(f"Amount of unique IP addresses:  {non_unique_ips}")
        print("-" * 50)

    except Exception as e:
        print(f"Error: {e}")

file_paths = ["../database/data/all-nodes.txt", "../database/data/exit-nodes.txt", "../database/data/bad-exit-nodes.txt"]

for file_path in file_paths:
    check_duplicates(file_path)
