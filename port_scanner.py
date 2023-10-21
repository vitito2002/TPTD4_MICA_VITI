# # import argparse
# # from scapy.all import *

# # def scan_port(target, port):
# #     src_port = RandShort()  # Puerto origen aleatorio
# #     response = sr1(IP(dst=target)/TCP(sport=src_port, dport=port, flags="S"), timeout=1, verbose=0)
# #     if response and response.haslayer(TCP):
# #         if response[TCP].flags == 0x12:  # Flags SYN-ACK
# #             return True
# #         elif response[TCP].flags == 0x14:  # Flags RST-ACK
# #             return False
# #     return None

# # def main():
# #     parser = argparse.ArgumentParser(description="Port Scanner usando Scapy")
# #     parser.add_argument("target", help="Dirección IP del host a escanear")
# #     args = parser.parse_args()

# #     open_ports = []
# #     filtered_ports = []
# #     total_ports = 0

# #     with open("port_scan_results.txt", "w") as results_file:
# #         for port in range(1, 6):  # Escanea puertos del 1 al 5
# #             total_ports += 1
# #             result = scan_port(args.target, port)
# #             if result is None:
# #                 filtered_ports.append(port)
# #             elif result:
# #                 open_ports.append(port)
# #                 results_file.write(f"Port {port}: Abierto\n")
# #             else:
# #                 results_file.write(f"Port {port}: Cerrado\n")

# #     print(f"Escaneo completo. Puertos abiertos: {len(open_ports)}, Puertos filtrados: {len(filtered_ports)}")
# #     print(f"Porcentaje de puertos abiertos: {len(open_ports) / total_ports * 100:.2f}%")

# # if __name__ == "__main__":
# #     main()

# # print(f'Time taken {end-start:.2f} seconds')

#########################################################################################################################################################
# import argparse
# import time
# from scapy.all import *

# def scan_port(target, port):
#     src_port = RandShort()  # Puerto origen aleatorio
#     response = sr1(IP(dst=target)/TCP(sport=src_port, dport=port, flags="S"), timeout=1, verbose=0)
#     if response and response.haslayer(TCP):
#         if response[TCP].flags == 0x12:  # Flags SYN-ACK
#             return True
#         elif response[TCP].flags == 0x14:  # Flags RST-ACK
#             return False
#     return None

# def main():
#     parser = argparse.ArgumentParser(description="Port Scanner usando Scapy")
#     parser.add_argument("target", help="Dirección IP del host a escanear")
#     args = parser.parse_args()

#     open_ports = []
#     closed_ports = []
#     filtered_ports = []
#     total_ports = 0

#     start = time.time()  # Inicio del temporizador

#     try:
#         with open("port_scan_results.txt", "w") as results_file:
#             for port in range(1, 5):  # Escanea puertos del 1 al 6
#                 total_ports += 1
#                 result = scan_port(args.target, port)
#                 if result is None:
#                     filtered_ports.append(port)
#                 elif result:
#                     open_ports.append(port)
#                     results_file.write(f"Port {port}: Abierto\n")
#                 else:
#                     closed_ports.append(port)
#                     results_file.write(f"Port {port}: Cerrado\n")
#     except Exception as e:
#         print(f"Error al escribir en el archivo: {str(e)}")


#     end = time.time()  # Fin del temporizador

#     print(f"Escaneo completo. Puertos abiertos: {len(open_ports)}, Puertos filtrados: {len(filtered_ports)}")
#     print(f"Porcentaje de puertos abiertos: {len(open_ports) / total_ports * 100:.2f}%")
#     print(f'Tiempo transcurrido: {end - start:.2f} segundos')

# if __name__ == "__main__":
#     main()

####este#####################################################################################################################################################
# import sys
# # import logging
# from scapy.all import *

# # Configurar Scapy para suprimir mensajes de depuración
# # logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

# def scan_ports(target_ip):
#     open_ports = []
#     closed_ports = []

#     for port in range(1, 6):
#         # Crear el paquete SYN
#         packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
#         # Enviar el paquete y recibir la respuesta
#         response = sr1(packet, timeout=1, verbose=0)

#         if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
#             # Si recibimos un paquete de respuesta con el flag SYN-ACK, el puerto está abierto.
#             open_ports.append(port)
#             print(f"Puerto {port} abierto")
#         else:
#             closed_ports.append(port)

#     with open("open_ports.txt", "w") as file:
#         file.write("Puertos abiertos:\n")
#         for port in open_ports:
#             file.write(f"Puerto {port} abierto\n")
        
#         file.write("\nPuertos cerrados:\n")
#         for port in closed_ports:
#             file.write(f"Puerto {port} cerrado\n")
        
#     print(f"Resultados guardados en open_ports.txt")

# if __name__ == "__main__":
#     if len(sys.argv) != 2:
#         print("Uso: python port_scanner.py <dirección_IP_del_host>")
#         sys.exit(1)

#     target_ip = sys.argv[1]
#     scan_ports(target_ip)


#########################################################################################################################################################
# import argparse
# import time
# from scapy.all import *

# def scan_port(target, port):
#     src_port = RandShort()  # Puerto origen aleatorio
#     response = sr1(IP(dst=target)/TCP(sport=src_port, dport=port, flags="S"), timeout=1, verbose=0)
#     if response and response.haslayer(TCP):
#         if response[TCP].flags == 0x12:  # Flags SYN-ACK
#             return True
#         elif response[TCP].flags == 0x14:  # Flags RST-ACK
#             return False
#     return None

# def main():
#     parser = argparse.ArgumentParser(description="Port Scanner usando Scapy")
#     parser.add_argument("target", help="Dirección IP del host a escanear")
#     args = parser.parse_args()

#     open_ports = []
#     closed_ports = []
#     filtered_ports = []
#     total_ports = 0

#     start = time.time()  # Inicio del temporizador

#     try:
#         with open("port_scan_results.txt", "w") as results_file:
#             for port in range(1, 6):  # Escanea puertos del 1 al 5
#                 total_ports += 1
#                 result = scan_port(args.target, port)
#                 if result is None:
#                     filtered_ports.append(port)
#                 elif result:
#                     open_ports.append(port)
#                     results_file.write(f"Port {port}: Abierto\n")
#                 else:
#                     closed_ports.append(port)
#                     results_file.write(f"Port {port}: Cerrado\n")
                    
#     except Exception as e:
#         print(f"Error al escribir en el archivo: {str(e)}")

#     end = time.time()  # Fin del temporizador

#     print(f"Escaneo completo. Puertos abiertos: {len(open_ports)}, Puertos cerrados: {len(closed_ports)}, Puertos filtrados: {len(filtered_ports)}")
#     print(f"Porcentaje de puertos abiertos: {len(open_ports) / total_ports * 100:.2f}%")
#     print(f'Tiempo transcurrido: {end - start:.2f} segundos')

# if __name__ == "__main__":
#     main()



import sys
import time
# import logging
from scapy.all import *

# Configurar Scapy para suprimir mensajes de depuración
# logging.getLogger("scapy.runtime").setLevel(logging.ERROR)

def scan_ports(target_ip):
    port_status = {}
    open_ports = 0
    total_ports = 0
    start = time.time()

    for port in range(1, 1001):
        # Crear el paquete SYN
        total_ports += 1
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        # Enviar el paquete y recibir la respuesta
        response = sr1(packet, timeout=0.5, verbose=0)

        if response and response.haslayer(TCP) and response.getlayer(TCP).flags == 0x12:
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
    print("open:", open_ports, "filtered:", total_ports-open_ports, "total:", total_ports)
    open_percentage = (open_ports / total_ports) * 100
    filtered_percentage = ((total_ports - open_ports) / total_ports) * 100
    print(f"Porcentaje de puertos abiertos: {open_percentage:.2f}%")
    print(f"Porcentaje de puertos filtrados: {filtered_percentage:.2f}%")
    print(f'Tiempo transcurrido: {end - start:.2f} segundos')

if __name__ == "__main__":
    if len(sys.argv) != 2:
        print("Uso: python port_scanner.py <dirección_IP_del_host>")
        sys.exit(1)

    target_ip = sys.argv[1]
    scan_ports(target_ip)
