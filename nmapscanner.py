import nmap

scanner = nmap.PortScanner()

print("Welcome, this is a simple nmap automation tool.")
print("<------------------------------------------------->")

ip_addr = input("Please enter your IP address: ")
print("The IP you entered is: ", ip_addr)
type(ip_addr)

# Asking for what scan they want to run.
response = input("""\nPlease enter the type of scan you want to run:
                    1) SYN ACK Scan
                    2) UDP Scan
                    3) Comprehensive Scan\n""")
print("You have selected option: ", response)

response_dict = {'1': ['-v -sS', 'tcp'], '2': ['-v -sU', 'udp'],
                 '3': ['-v -sS -sV -sC -A -O', 'tcp,udp']}

# Now validate the input
if response not in response_dict.keys():
    print("Enter a valid option.")
else:
    print("Nmap Version: ", scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024', response_dict[response][0])
    print(scanner.scaninfo())

    protocols = response_dict[response][1].split(",")
    for protocol in protocols:
        if protocol in scanner[ip_addr]:
            print(f"Protocol {protocol} is open on:")
            open_ports = scanner[ip_addr][protocol].keys()
            for port in open_ports:
                if scanner[ip_addr][protocol][port]['state'] == 'open':
                    print(f"Port {port} is open on {ip_addr}")
        else:
            print(f"{ip_addr} is down.")
