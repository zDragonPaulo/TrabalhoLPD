# Paulo Abade - 23919
# Mestrado de Engenharia de Segurança Informática
# Iniciado em 19/10/2025
# Última atualização: 24/01/2026
# PortKnocking


from scapy.all import IP, TCP, send
import time
import ipaddress

def knock():
    """
    Executa a sequência de 'batidas' (knocks) num IP alvo.

    A função interage com o utilizador para definir o alvo e a sequência 
    de portas. Utiliza o Scapy para construir pacotes TCP com a flag SYN 
    personalizada, garantindo que a sequência é enviada com intervalos 
    controlados para evitar problemas de race condition no processamento do servidor.

    Análise Técnica:
        - Protocolo: TCP Camada 4.
        - Flags: SYN ("S").
        - Intervalo: 1 segundo entre pacotes para integridade da sequência.
    """
    print("\n--- Port Knocking Client ---")

    # Validação do endereço IP do alvo
    is_an_ip = False
    target_ip = ""
    while not is_an_ip:
        target_ip = input("Insira o IP do servidor (ex: 192.168.1.86): \n")
        try:
            ip_obj = ipaddress.ip_address(target_ip)
            is_an_ip = True
        except ValueError:
            print("Erro: Formato de IP inválido")

    # Definição do tamanho da sequência
    num_ports = 0
    while num_ports <= 0:
        try:
            num_ports = int(input("Quantas portas tem a sequência de knock? "))
            if num_ports <= 0: 
                print("Insira um número maior que zero.")
        except ValueError:
            print("Erro: Insira um número inteiro.")

    # Construção da lista de portas (A "combinação" do cofre)
    ports = []
    print(f"Insira as {num_ports} portas pela ordem correta:")
    while len(ports) < num_ports:
        try:
            chosen_port = int(input(f"Porta {len(ports) + 1}: "))
            if 1 <= chosen_port <= 65535:
                ports.append(chosen_port)
            else:
                print("Erro: A porta deve estar entre 1 e 65535.")
        except ValueError:
            print("Erro: Insira um número de porta válido.")

    print(f"\n[*] A iniciar sequência de knock para {target_ip}...")

    # Execução do sequenciamento de pacotes
    for port in ports:
        # Construção do pacote IP/TCP com flag SYN
        # O servidor não precisa de responder, apenas de registar a tentativa de ligação
        packet = IP(dst=target_ip) / TCP(dport=port, flags="S")
        
        # Envio do pacote sem output detalhado
        send(packet, verbose=False)
        
        print(f"[+] Knock enviado para a porta: {port}")
        
        # O sleep é crucial para que o daemon do servidor (ex: knockd) 
        # processe os logs na ordem correta
        time.sleep(1) 

    print("[!] Sequência completada. Tente aceder ao serviço agora.")