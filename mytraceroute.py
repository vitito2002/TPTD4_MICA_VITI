from scapy.all import *
from sys import argv
import time

# if __name__ == '__main__':
#     if len(argv) != 2 or argv[1][0] != '-' or len(argv[1]) > 50:
#         print('Modo de uso:\n python mytraceroute.py -{URL host destino}')
#         quit()

#     direccionIPDst = argv[1][1:]
#     packet = IP(dst= direccionIPDst, ttl = 64)/ICMP(type=8, code=0)
#     resp = sr1(packet, timeout = 10)




def mytraceroute(destination_host, max_ttl):     # Maximum TTL value 
    
    for ttl in range(1, max_ttl+1):  
        packet = IP(dst=destination_host, ttl=ttl) / ICMP()
        start=time.time()
        resp = sr1(packet, timeout=10, verbose=False)
        end=time.time()
        if resp is None:
            print(f"{ttl}: *")
        elif resp.haslayer(ICMP) and resp[ICMP].type == 11 and resp[ICMP].code == 0:
            print(f"{ttl}: {resp.src},(Time: {1000 * (end_time - start_time):.2f} ms)")
        elif resp.haslayer(ICMP) and resp[ICMP].type == 0:
            print(f"{ttl}: {resp.src} (Destination Reached),(Time: {1000 * (end_time - start_time):.2f} ms)")
            break
        else:
            print(f"{ttl}: Unknown Response")


if __name__ == '__main__':
    if len(argv) != 2:
        print('Modo de uso:\n python mytraceroute.py {URL o dirección IP}')
        quit()

    destination_host = argv[1]
    mytraceroute(destination_host, 30)