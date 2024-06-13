# ARP Spoofing tool made by green_monster

## 0. Environment Setting
- OS: Mac book air M1
- python version: 3.12.3

## 1. Scenario
- victim: windows laptop
- attacker: Mac book air M1

Performed ARP Spoofing attack from the same LAN and sniffed the packets going from windows pc to the gateway(It's basically MITM attack)

## 2. Description
### 2-1. banner.py
It is just a simple code that prints out my banner :)

### 2-2. arp_spoofing.py
1) **enable_iproute**

This one allows the victim to connect to internet in the middle of the attack. If this part doesn't work, the victim won't be able to use the internet because the packets are all sent to the attacker not the gateway

2) **get_mac**

This is where you can get the mac address of the gateway and the target machine.

3) **arp_spoof**

Sends spoofed ARP packets to the victim and the gateway. Since this process needs to be continued while we are sniffing, it will be executed by multi-thread until keyboard interrupt is detected.

4) **recover_arp**

Once the attack is finished, sends normal arp packets to recover ARP table of the gateway and victim.

## 3. Flow
First you need to start the virtual-environment setting.
```
git clone 
```
