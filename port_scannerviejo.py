import sys
from scapy.all import *



def syn_scan(target_ip, timeout):
    port_status = {}
    open_ports = 0
    total_ports = 0

    for port in range(1, 1001):
        total_ports += 1

        # SYN scan logic
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        response = sr1(packet, timeout=timeout, verbose=0)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            open_ports += 1
            port_status[port] = "open"
            print(f"Port {port} is open (SYN scan)")
        else:
            port_status[port] = "filtered"

    return open_ports, total_ports, port_status

def connect_scan(target_ip, timeout):
    port_status = {}
    open_ports = 0
    total_ports = 0

    for port in range(1, 1001):
        total_ports += 1

        # Connect scan logic using Scapy
        packet = IP(dst=target_ip) / TCP(dport=port, sport=2002, flags="S")
        response = sr1(packet, timeout=timeout, verbose=0)
        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            # try:
            # Crear un paquete con el tercer mensaje del handshake (con payload)
            ack_packet = IP(dst=target_ip) / TCP(dport=port, sport=packet[TCP].sport, ack=response[TCP].seq + 1, seq=packet[TCP].seq+1, flags="A") / f"GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n" #GET / HTTP/1.1\r\nHost: {target_ip}\r\n\r\n Hello, {target_ip}!
            # Enviar el paquete de ACK con payload
            response = sr1(ack_packet, timeout=timeout, verbose=0)
            if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x10:
                # Si recibimos un ACK en respuesta, el puerto estÃ¡ abierto.
                open_ports += 1
                port_status[port] = "open"
                print(f"Port {port} is open (Connect scan)")
            else:
                port_status[port] = "filtered"
        # except Exception as e:
        #     port_status[port] = "error"
        else:
            port_status[port] = "filtered"

    return open_ports, total_ports, port_status


def scan_ports(target_ip, option, timeout):
    # SYN scan
    if option == "-h":
        print("SYN scan:")
        open_ports, total_ports, port_status = syn_scan(target_ip, timeout)
        with open("open_ports_synscan.txt", "w") as file:
            file.write(f"=== Target IP address {target_ip} ===\n")
            for port, status in port_status.items():
                file.write(f"Port {port} - Status: {status}\n")

    # CONNECT scan
    elif option == "-f":
        print("Connect scan:")
        open_ports, total_ports, port_status = connect_scan(target_ip, timeout)
        with open("open_ports_conscan.txt", "w") as file:
            file.write(f"=== Target IP address {target_ip} ===\n")
            for port, status in port_status.items():
                file.write(f"Port {port} - Status: {status}\n")
    else:
        print("Usage for port scanner: (sudo) python network_tools.py <host_IP_address> -h (SYN)|-f (CONNECT)")
        sys.exit(1)

    
    print("Finito.")
    print("Open:", open_ports, "Filtered:", total_ports - open_ports, "Total:", total_ports)
    open_percentage = (open_ports / total_ports) * 100
    filtered_percentage = ((total_ports - open_ports) / total_ports) * 100
    print(f"Percentage of open ports: {open_percentage:.2f}%")
    print(f"Percentage of filtered ports: {filtered_percentage:.2f}%")

    return open_ports, total_ports, port_status, open_percentage, filtered_percentage


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("\n Usage for port scanner: (sudo) python network_tools.py <host_IP_address> -h|-f\n")
        sys.exit(1)

    target_ip = sys.argv[1]
    option = sys.argv[2] if len(sys.argv) == 3 else None

    scan_ports(target_ip, option, 0.5)

... (1 line left)
