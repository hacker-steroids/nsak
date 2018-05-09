# Network Swiss Army Knife - nsak
An all-in-one tool that has the ability to perform network scanning, man in the middle attacks, operations on packets, OS fingerprinting and other network based attacks. The tool is written in Python and utilizes Scapy and nmap modules.

Check project status [here](#Project-Development)

## Functionality
- packet sniffing
- packet injection
- packet manipulation
- ARP spoofing
- OS Fingerprinting (Passive and Active)
- other passive or active attacks
- other MiTM attacks

## Usages:
To perform ARP spoofing:
```
$ python nsak.py -as -i <interface> -t <target IP> -g <router IP>
```
To perform packet sniffing:
```
$ python nsak.py -S -i <interface>
```


## Project Development:
### Accomplished:
- ARP spoofing
- Packet sniffing (able to view victim's urls)

### TODOS:
- Packet injection
- Packet manipulation
- OS Fingerprinting

## Software:
- Kali Linux
- Python
- Scapy

## Hardware:
- Raspberry Pi

## Resources:
- http://scapy.readthedocs.io/en/latest/
- https://scapy.net/demo.html
- http://bt3gl.github.io/black-hat-python-infinite-possibilities-with-the-scapy-module.html
- https://0x00sec.org/t/quick-n-dirty-arp-spoofing-in-python/487
- https://null-byte.wonderhowto.com/how-to/build-arp-scanner-using-scapy-and-python-0162731/
- https://null-byte.wonderhowto.com/how-to/build-dns-packet-sniffer-with-scapy-and-python-0163601/
- https://medium.com/@ismailakkila/black-hat-python-arp-cache-poisoning-with-scapy-7cb1d8b9d242
- https://medium.com/@ismailakkila/black-hat-python-parsing-http-payloads-with-scapy-d937d01af9b1
- http://www.cs.dartmouth.edu/~sergey/netreads/local/reliable-dns-spoofing-with-python-twisting-in-arp-poisoning-pt-2.html
- https://null-byte.wonderhowto.com/how-to/build-man-middle-tool-with-scapy-and-python-0163525/
- https://null-byte.wonderhowto.com/how-to/hack-like-pro-using-powerful-versatile-scapy-for-scanning-dosing-0159231/
- https://yamakira.github.io/art-of-packet-crafting-with-scapy/network_recon/os_detection/index.html
- http://www.secdev.org/conf/scapy_hack.lu.pdf
- https://www.hackingloops.com/scapy/
