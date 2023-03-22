import nmap


scanner = nmap.PortScanner()

print ("Welcome,this is a simple nmap automation tool.")
print("<------------------------------------------------->")

ip_addr = input("Please enter your IP address:")
print ("The IP You entered is: ", ip_addr)
type(ip_addr)
 

# Asking for what scan they want to run.

response = input(""" \n Please enter the type of sca you want to run: 
                        1)SYN ACK Scan
                        2)UDP Scan
                        3)Comprehensive Scan\n""")

print("You have selected option: " , response)


response_dict = {'1' : ['-v -sS', 'tcp'], '2' : [ '-v -sU', 'udp'], '3': ['-v -sS -sV -sC -A -O', 'tcp']}
# Now validate the input

if response not in response_dict.keys():
    print("Enter a valid option.")
else:
    print("Nmap Version: " , scanner.nmap_version())
    scanner.scan(ip_addr, '1-1024' , response_dict[response][0])
    print(scanner.scaninfo())

    if scanner.scaninfo() == 'up':
        print("scanner status: ", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Ope ports: ", scanner[ip_addr][response_dict[response][1]].keys())
    

    
      


# else:
#     print("Nmap Version: " , scanner.nmap_version())
#     scanner.scan(ip_addr, '1-1024' ,  response_dict[response[1]])
#     print(scanner.scaninfo())
#     print("IP status: ", scanner[ip_addr].state())
#     print(scanner[ip_addr].all_protocols())
#     # Now describig the all open ports
#     print("Open ports: " , scanner[ip_addr]['udp'].keys())


# elif response_dict[response[2]]:
#     print("Nmap Version: " , scanner.nmap_version())
#     scanner.scan(ip_addr, '1-1024' , response_dict[response[2]])
#     print(scanner.scaninfo())
#     print("IP status: ", scanner[ip_addr].state())
#     print(scanner[ip_addr].all_protocols())
#     # Now describig the all open ports
#     print("Open ports: " , scanner[ip_addr]['tcp'].keys())
# elif response >= '4' :
#     print ("Please select the right option.")


