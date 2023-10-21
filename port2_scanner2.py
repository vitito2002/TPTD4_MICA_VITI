# # import sys
# # import time
# # # import logging
# # from scapy.all import *

# # # Configurar Scapy para suprimir mensajes de depuración
# # # logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# # def scan_ports(target_ip):
# #     port_status = {}
# #     open_ports = 0
# #     total_ports = 0
# #     start = time.time()

# #     for port in range(1, 1001):
# #         # Crear el paquete SYN
# #         total_ports += 1
# #         packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
# #         # Enviar el paquete y recibir la respuesta
# #         response = sr1(packet, timeout=0.5, verbose=0)

# #         if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
# #             # Si recibimos un paquete de respuesta con el flag SYN-ACK, el puerto está abierto.
# #             open_ports += 1
# #             port_status[port] = "abierto"
# #             print(f"Puerto {port} abierto")
# #         else:
# #             port_status[port] = "filtrado"

# #     with open("open_ports.txt", "w") as file:
# #         for port, status in port_status.items():
# #             file.write(f"Puerto {port} - Estado: {status}\n")
    
# #     end = time.time()

# #     print(f"Finito")
# #     print("open:", open_ports, "filtered:", total_ports-open_ports, "total:", total_ports)
# #     open_percentage = (open_ports / total_ports) * 100
# #     filtered_percentage = ((total_ports - open_ports) / total_ports) * 100
# #     print(f"Porcentaje de puertos abiertos: {open_percentage:.2f}%")
# #     print(f"Porcentaje de puertos filtrados: {filtered_percentage:.2f}%")
# #     print(f'Tiempo transcurrido: {end - start:.2f} segundos')

# # if __name__ == "__main__":
# #     if len(sys.argv) != 2:
# #         print("Uso: python port_scanner.py <dirección_IP_del_host>")
# #         sys.exit(1)

# #     target_ip = sys.argv[1]
# #     scan_ports(target_ip)



import sys
import time
from scapy.all import *

def scan_ports(target_ip, option):
    if option != "-h" and option != "-f":
        print("Uso: python port_scanner.py <dirección_IP_del_host> -h|-f")
        sys.exit(1)

    port_status = {}
    open_ports = 0
    total_ports = 0
    start = time.time()

    for port in range(1, 1001):
        # Crear el paquete SYN
        total_ports += 1
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        # Enviar el paquete y recibir la respuesta
        response = sr1(packet, timeout=0.3, verbose=0)

        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
            if option == "-f":
                # Crear un paquete con el tercer mensaje del handshake (con payload)
                ack_packet = IP(dst=target_ip) / TCP(dport=port, sport=response[TCP].dport, flags="A") / "GET / HTTP/1.1\r\nHost: www.google.com\r\n\r\n"
                # Enviar el paquete de ACK con payload
                response = sr1(ack_packet, timeout=0.3, verbose=0)
                if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x18:
                    # Si recibimos un ACK en respuesta, el puerto está abierto.
                    open_ports += 1
                    port_status[port] = "abierto"
                    print(f"Puerto {port} abierto")
                else:
                    port_status[port] = "filtrado"
            else:
                # Si recibimos un paquete de respuesta con el flag SYN-ACK, el puerto está abierto.
                open_ports += 1
                port_status[port] = "abierto"
                print(f"Puerto {port} abierto")
        else:
            port_status[port] = "filtrado"

    with open("open_ports.txt", "w") as file:
        for port, status in port_status.items():
            file.write(f"Puerto {port} - Estado: {status}\n")
    
    end = time.time()

    print(f"Finito")
    print("open:", open_ports, "filtered:", total_ports - open_ports, "total:", total_ports)
    open_percentage = (open_ports / total_ports) * 100
    filtered_percentage = ((total_ports - open_ports) / total_ports) * 100
    print(f"Porcentaje de puertos abiertos: {open_percentage:.2f}%")
    print(f"Porcentaje de puertos filtrados: {filtered_percentage:.2f}%")
    print(f'Tiempo transcurrido: {end - start:.2f} segundos')

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Uso: python port_scanner.py <dirección_IP_del_host> -h|-f")
        sys.exit(1)

    target_ip = sys.argv[1]
    option = sys.argv[2]
    scan_ports(target_ip, option)


# import sys
# import time
# import argparse
# from scapy.all import *

# def syn_scan(target_ip):
#     # ... (Your existing SYN scan code)

# def connection_scan(target_ip):
#     # ... (Code for the connection scan)

# def main():
#     parser = argparse.ArgumentParser(description="Port Scanner")
#     parser.add_argument("target_ip", help="Target IP address")
#     parser.add_argument("-t", "--type", choices=["-h", "-f"], required=True, help="Scan type: -h for SYN scan, -f for connection scan")

#     args = parser.parse_args()

#     if args.type == "-h":
#         syn_scan(args.target_ip)
#     elif args.type == "-f":
#         connection_scan(args.target_ip)
#     else:
#         print("Invalid scan type. Use -h for SYN scan or -f for connection scan.")
#         sys.exit(1)

# if __name__ == "__main__":
#     main()
