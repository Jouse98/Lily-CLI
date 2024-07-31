import sys
import os
import nmap

scanner = nmap.PortScanner()

try:
    command = sys.argv[1]
except:  # noqa: E722
    print("Something went wrong! Did you provide a command?")
    command = ''
args = sys.argv[2:]



def install(command, args):
    if command == 'gitinstall':
        try:
            os.system('git clone ' + args[0])
        except:  # noqa: E722
            print('Something went wrong! Do you have git installed? did you provide a valid url?')
            
    elif command == 'pipinstall':
        
        try:
            os.system('pip install ' + args[0])
        except:  # noqa: E722
            print('Something went wrong! Use "install pip" to install pip if you dont have it yet!')
            
    elif command == 'install' and args[0] == 'pip':
        try:
            os.system('git clone https://github.com/pypa/pip.git')
        except:  # noqa: E722
            print('Something went wrong! Do you have git installed?')
            
    elif command == 'install' and args[0] == 'nmap':
        try:
            os.system('git clone https://github.com/nmap/nmap.git')
        except:  # noqa: E722
            print('Something went wrong! Do you have git installed?')
            
    elif command == 'install' and args[0] == 'pythonmap':
        try:
            os.system('git clone https://github.com/ernw/pythonmap.git')
        except:  # noqa: E722
            print('Something went wrong! Do you have git installed?')
    
    elif command == 'install' and args[0] == 'hydra':
        try:
            os.system('git clone https://github.com/vanhauser-thc/thc-hydra.git')
        except:  # noqa: E722
            print('Something went wrong! Do you have git installed?')

def help():
    if command == 'help':
        print('''
            Commands:
                gitinstall <url>                # Install a git repository
                pipinstall <package>            # Install a package 
                help                            # Show this message
                nmap                            # Run nmap
                
                install:                          (git)
                    pip                           # Install pip
                    nmap                          # Install nmap
                    pythonmap                     # Install pythonmap
                    hydra                         # Install hydra
        ''')

def nmap():
    if command == 'nmap':
        ip_addr = input("Enter the IP address you want to scan: ")
        response = input("""\nPlease enter the type of scan you want to run
                1. SYN ACK Scan
                2. UDP Scan
                3. Comprehensive Scan
                4. Regular Scan
                5. OS Detection
                6. Multiple IP inputs
                7. Ping Scan\n""")
    print("You have selected option: ", response,'! Now loading...')

    # If user's input is 1, perform a SYN/ACK scan
    if response == '1':
        print("Nmap Version: ", scanner.nmap_version())
        # Here, v is used for verbose, which means if selected it will give extra information
        # 1-1024 means the port number we want to search on
        #-sS means perform a TCP SYN connect scan, it send the SYN packets to the host
        scanner.scan(ip_addr,'1-1024', '-v -sS')
        print(scanner.scaninfo())
        # state() tells if target is up or down
        print("Ip Status: ", scanner[ip_addr].state())
        # all_protocols() tells which protocols are enabled like TCP UDP etc
        print("protocols:",scanner[ip_addr].all_protocols())
        print("Open Ports: ", scanner[ip_addr]['tcp'].keys())

    # If user's input is 2, perform a UDP Scan   
    elif response == '2':
        # Here, v is used for verbose, which means if selected it will give #extra information
        # 1-1024 means the port number we want to search on
        #-sU means perform a UDP SYN connect scan, it send the SYN packets to #the host
        print("Nmap Version: ", scanner.nmap_version())
        scanner.scan(ip_addr, '1-1024', '-v -sU')
        print(scanner.scaninfo())
        # state() tells if target is up or down
        print("Ip Status: ", scanner[ip_addr].state())
        # all_protocols() tells which protocols are enabled like TCP UDP etc
        print("protocols:",scanner[ip_addr].all_protocols())
        print("Open Ports: ", scanner[ip_addr]['udp'].keys())

    # If user's input is 3, perform a Comprehensive scan
    elif response == '3':
        print("Nmap Version: ", scanner.nmap_version())
        # sS for SYN scan, sv probe open ports to determine what service and version they are running on
        # O determine OS type, A tells Nmap to make an effort in identifying the target OS
        scanner.scan(ip_addr, '1-1024', '-v -sS -sV -sC -A -O')
        print(scanner.scaninfo())
        print("Ip Status: ", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Open Ports: ", scanner[ip_addr]['tcp'].keys())

    # If user's input is 4, perform a Regular Scan
    elif response == '4':
        # Works on default arguments
        scanner.scan(ip_addr)
        print(scanner.scaninfo())
        print("Ip Status: ", scanner[ip_addr].state())
        print(scanner[ip_addr].all_protocols())
        print("Open Ports: ", scanner[ip_addr]['tcp'].keys())
    # If user's input is 5, perform a OS Detection
    elif response == '5':
        print(scanner.scan("127.0.0.1", arguments="-O")['scan']['127.0.0.1']['osmatch'][1])
    # If user's input is 6, perform a Multiple IP inputs
    elif response == '6':
        ip_addr = input()
        print("Nmap Version: ", scanner.nmap_version())
        # Here, v is used for verbose, which means if selected it will give extra information
        # 1-1024 means the port number we want to search on
        #-sS means perform a TCP SYN connect scan, it send the SYN packets to the host
        scanner.scan(ip_addr,'1-1024', '-v -sS')
        print(scanner.scaninfo())
        # state() tells if target is up or down
        print("Ip Status: ", scanner[ip_addr].state())
        # all_protocols() tells which protocols are enabled like TCP UDP etc
        print("protocols:",scanner[ip_addr].all_protocols())
        print("Open Ports: ", scanner[ip_addr]['tcp'].keys())

    # If user's input is 7, perform a ping scan
    elif response == '7': 
        scanner.scan(hosts='192.168.1.0/24', arguments='-n -sP -PE -PA21,23,80,3389')
        hosts_list = [(x, scanner[x]['status']['state']) for x in scanner.all_hosts()]
        for host, status in hosts_list:
            print('{0}:{1}'.format(host, status))

    # If user's input is not valid
    else:
        print("Please choose a number from the options above")

if 'install' in command:
    install(command, args)
elif command == 'help':
    help()
elif command == 'nmap':
    nmap()