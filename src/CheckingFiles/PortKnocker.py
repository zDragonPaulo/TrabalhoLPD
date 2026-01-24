# Paulo Abade - 23919
# Mestrado de Engenharia de Segurança Informática
# Iniciado em 19/10/2025
# Última atualização: 24/01/2026
# PortKnocking


from scapy.all import IP, TCP, send
import time

def knock(target_ip, ports):
    # Desta maneira, pode receber um grande número de portas
    for port in ports:
        p = IP(dst=target_ip) / TCP(dport=port, flags="S")
        send(p, verbose=False)
        print(f"Knock Knock: {port}")
        time.sleep(1) # Garante que a ordem fica correta


# Validar o endereço IP
is_an_ip = False
while not is_an_ip:
    target_ip = input("Insira um IP dentro da sua rede privada (ex: 192.168.1.254): \n")
    try:
        ip_obj = ipaddress.ip_address(target_ip)
        is_an_ip = True
    except ValueError:
        print("Erro: Formato de IP inválido")


num_ports = 0
while num_ports <= 0:
    try:
        num_ports = int(input("Quantas portas tem a sequência de knock? "))
        if num_ports <= 0: 
            print("Insira um número maior que zero.")
    except ValueError:
        print("Erro: Insira um número inteiro.")

ports_sequence = []
print(f"Insira as {num_ports} portas pela ordem correta:")

while len(ports_sequence) < num_ports:
    try:
        chosen_port = int(input(f"Porta {len(ports_sequence) + 1}: "))
        if 1 <= chosen_port <= 65535:
            ports_sequence.append(chosen_port)
        else:
            print("Erro: A porta deve estar entre 1 e 65535.")
    except ValueError:
        print("Erro: Insira um número de porta válido.")

knock(target_ip,ports_sequence)