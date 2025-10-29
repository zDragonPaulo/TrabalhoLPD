# Paulo Abade - 23919
# Mestrado de Engenharia de Segurança Informática
# Iniciado em 29/10/2025
# Última atualização: 29/10/2025

import nmap
import ipaddress

def nmap_scan():
    print("Verificação de Portas de um Endereço IP\n")
    # Validar o endereço IP
    while True:
        target_ip = input("Insira um IP dentro da sua rede privada (ex: 192.168.1.254): \n")
        try:
            ip_obj = ipaddress.ip_address(target_ip)
            if ip_obj.is_private:
                break
            print("Erro: Insira um IP privado (192.168.x.x, 10.x.x.x, 172.16-31.x.x)")
        except ValueError:
            print("Erro: Formato de IP inválido")

    # Validar as portas (1-65535)
    while True:
        try:
            target_port_min = int(input("Insira a porta inicial (1-65535): \n"))
            if 1 <= target_port_min <= 65535:
                break
            print("Erro: A porta deve estar entre 1 e 65535")
        except ValueError:
            print("Erro: Insira apenas números")
    
    while True:
        try:
            target_port_max = int(input(f"Insira a porta final ({target_port_min}-65535): \n"))
            if target_port_min <= target_port_max <= 65535:
                break
            print(f"Erro: A porta deve estar entre {target_port_min} e 65535")
        except ValueError:
            print("Erro: Insira apenas números")
        
    scanner = nmap.PortScanner()
    port_range = f"{target_port_min}-{target_port_max}"
    try:
        # '-sT' faz TCP connect (não requer privilégios administrativos). Muda para '-sS' se tiveres privilégios.
        scanner.scan(target_ip, port_range, arguments='-sT')
    except nmap.PortScannerError as e:
        print("Erro ao executar nmap:", e)
        return

    if target_ip not in scanner.all_hosts():
        print("Host não respondeu ao scan (host down ou bloqueado por firewall).")
        return

    tcp_info = scanner[target_ip].get('tcp', {})
    for port in range(target_port_min, target_port_max + 1):
        info = tcp_info.get(port)
        if info:
            state = info.get('state', 'unknown')
            print(f"Porta {port} está {state}") 
        else:
            print(f"Porta {port} está closed/filtered (sem informação)")
