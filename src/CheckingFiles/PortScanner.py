# Paulo Abade - 23919
# Mestrado de Engenharia de Segurança Informática
# Iniciado em 29/10/2025
# Última atualização: 06/02/2026

import nmap
import ipaddress

def nmap_scan():
    """
    Executa uma varredura de portas TCP num endereço IP e intervalo definidos.

    A função utiliza o método TCP Connect Scan (`-sT`), que completa o 
    handshake de três vias do TCP. Este método é fiável e não requer 
    privilégios de root, embora seja mais facilmente detetável por sistemas 
    de deteção de intrusão (IDS).

    Metodologia:
        1. Validação de Input: Garante que o IP e o range de portas são válidos.
        2. Scanning: O Nmap interage com a pilha de rede para testar as portas.
        3. Parsing: Os resultados são extraídos do objeto scanner para exibição.
    """
    print("--- Reconhecimento de Rede: Port Scanner ---\n")
    
    # Validação do endereço IP alvo
    is_an_ip = False
    target_ip = ""
    while not is_an_ip:
        target_ip = input("Insira um IP dentro da sua rede privada (ex: 192.168.1.254): \n")
        try:
            ip_obj = ipaddress.ip_address(target_ip)
            is_an_ip = True
        except ValueError:
            print("Erro: Formato de IP inválido")

    # Validação do intervalo de portas (Port Range)
    isnumber1 = False
    target_port_min = 1
    while not isnumber1:
        try:
            target_port_min = int(input("Insira a porta inicial (1-65535): \n"))
            if 1 <= target_port_min <= 65535:
                isnumber1 = True
            else:
                print("Erro: A porta deve estar entre 1 e 65535")
        except ValueError:
            print("Erro: Insira apenas números")
    
    isnumber2 = False
    target_port_max = 65535
    while not isnumber2:
        try:
            target_port_max = int(input(f"Insira a porta final ({target_port_min}-65535): \n"))
            if target_port_min <= target_port_max <= 65535:
                isnumber2 = True
            else:
                print(f"Erro: A porta deve estar entre {target_port_min} e 65535")
        except ValueError:
            print("Erro: Insira apenas números")
        
    # Inicialização do motor Nmap
    scanner = nmap.PortScanner()
    port_range = f"{target_port_min}-{target_port_max}"
    
    print(f"[*] A realizar scan em {target_ip} (Portas: {port_range})...")
    
    try:
        # Argumento -sT: TCP Connect Scan
        # Garante maior compatibilidade sem necessidade de privilégios administrativos
        scanner.scan(target_ip, port_range, arguments='-sT')
    except nmap.PortScannerError as e:
        print("Erro ao executar nmap:", e)
        return

    # Verificação de disponibilidade do host
    if target_ip not in scanner.all_hosts():
        print("[!] Host não respondeu (pode estar offline ou a bloquear pacotes ICMP/Portas).")
        return

    # Extração e exibição dos resultados
    tcp_info = scanner[target_ip].get('tcp', {})
    print(f"\nResultados para o host: {target_ip}")
    print("-" * 30)
    port_info=[]
    for port in range(target_port_min, target_port_max + 1):
        info = tcp_info.get(port)
        if info:
            state = info.get('state', 'unknown')
            # 'open' significa que um serviço está à escuta nesta porta
            print(f"Porta {port:5} | Estado: {state}") 
            if state == "open":
                port_info.append((f"Porta {port:5} | Estado: {state}"))
        else:
            # Se não houver info, a porta é considerada fechada ou filtrada por firewall
            print(f"Porta {port:5} | Estado: closed/filtered")
    print("-" * 30)
    print("Estão abertas as portas:")
    for info in port_info:
        print(info)
    print("-" * 30)
