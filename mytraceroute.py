import sys
import time
from scapy.all import *

def traceroute(destination_host, max_ttl):     # Maximum TTL value 
    print(f"Tracing route to {destination_host}")

    ttl_zero_during_transit_count = 0
    no_response_count = 0
    destination_reached_count = 0
    total_count = 0

    for ttl in range(1, max_ttl+1):  
        packet = IP(dst=destination_host, ttl=ttl) / ICMP(type=8, code=0)
        # packet.show()
        total_count += 1

        start_time = time.time()
        resp = sr1(packet, timeout=1, verbose=False)
        end_time = time.time()
        
        if resp is None:
            no_response_count += 1
            print(f"{ttl}: *")

        elif resp.haslayer(ICMP) and resp[ICMP].type == 11 and resp[ICMP].code == 0:
            ttl_zero_during_transit_count += 1
            print(f"{ttl}: {resp.src} (Time: {1000 * (end_time - start_time):.2f} ms)")

        elif resp.haslayer(ICMP) and resp[ICMP].type == 0:
            destination_reached_count += 1
            print(f"{ttl}: {resp.src} (Destination Reached) (Time: {1000 * (end_time - start_time):.2f} ms)")
            break
        else:
            print(f"{ttl}: Unknown Response")

    # total_count = max_ttl  # Número total de saltos
    percentage_ttl_zero_during_transit = (ttl_zero_during_transit_count / total_count) * 100
    percentage_no_response = (no_response_count / total_count) * 100
    destination_reached = (destination_reached_count)

    print("---")
    print(f"Porcentaje de hosts intermedios que envían mensajes de ttl-zero-during-transit: {percentage_ttl_zero_during_transit:.2f}%")
    print(f"Porcentaje de hosts intermedios que no responden: {percentage_no_response:.2f}%")
    print(f"Porcentaje de hosts intermedios que responden como destino final: {destination_reached:d} (si es 1 significa que llegó al host destino final, caso contrario no)")
    print("---")

    return percentage_no_response, percentage_ttl_zero_during_transit, destination_reached



if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("\n Usage for traceroute: (sudo) python traceroute.py <host_IP_address>\n")
        sys.exit(1)

    target_ip = sys.argv[1]
    print("Traceroute:")
    traceroute(target_ip, max_ttl=45) #como windows