import socket
import struct
import csv
import datetime

def analyze_packet(packet):
    # Lógica de análise do pacote capturado (substitua com sua lógica específica)
    # Verifique as condições específicas no pacote e atribua o status adequado

    # Exemplo: Verificar se o pacote possui um determinado valor no campo de destino
    if packet[16] == b'\x00\x00\x00\x00':
        status = "Suspeito"
    else:
        status = "OK"

    return status

def monitor_traffic(interface):
    # Cria um socket de monitoramento de pacotes
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
    sock.bind((interface, 0))

    print(f"Monitorando o tráfego na interface {interface}...")

    try:
        with open("data.csv", "w", newline="") as csvfile:
            fieldnames = ["src_ip", "src_mac", "dst_mac", "status", "timestamp"]
            writer = csv.DictWriter(csvfile, fieldnames=fieldnames)
            writer.writeheader()

            while True:
                # Recebe um pacote
                packet, _ = sock.recvfrom(65536)

                # Extrai as informações do pacote
                eth_header = struct.unpack('!6s6sH', packet[:14])
                src_mac = ':'.join(f'{byte:02x}' for byte in eth_header[1])
                dst_mac = ':'.join(f'{byte:02x}' for byte in eth_header[0])

                # Obtém o endereço IP de origem
                ip_header = packet[14:34]
                ip_fields = struct.unpack('!BBHHHBBH4s4s', ip_header)
                src_ip = socket.inet_ntoa(ip_fields[8])

                # Realiza a análise do pacote
                status = analyze_packet(packet)

                # Obtém a data e hora atual
                timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")

                # Armazena as informações do pacote no arquivo CSV
                writer.writerow({"src_ip": src_ip, "src_mac": src_mac, "dst_mac": dst_mac, "status": status, "timestamp": timestamp})

                # Exibe as informações do pacote
                print(f"Endereço IP de origem: {src_ip}")
                print(f"MAC de origem: {src_mac}")
                print(f"MAC de destino: {dst_mac}")
                print(f"Status: {status}")
                print(f"Data e Hora: {timestamp}")
                print("")

    except KeyboardInterrupt:
        print("\nMonitoramento interrompido.")

    finally:
        # Fecha o socket
        sock.close()


# Exemplo de uso
interface = "enp3s0"  # Interface de rede para monitorar (substitua com a sua interface)

monitor_traffic(interface)
