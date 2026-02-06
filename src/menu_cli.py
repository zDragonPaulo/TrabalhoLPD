# Paulo Abade - 23919
# Mestrado de Engenharia de Segurança Informática
# Iniciado em 19/10/2025
# Última atualização: 06/02/2026

# É o menu da aplicação

def print_menu():
    """
    Exibe a interface gráfica textual (CLI) com as opções disponíveis.
    """
    print("\n" + "="*45)
    print("      CENTRAL DE OPERAÇÕES DE SEGURANÇA")
    print("="*45)
    print(" 1 - Port Checking (Enumeração Nmap)")
    print(" 2 - DoS (Network Stress Test)")
    print(" 3 - SYN Flood (TCP Vulnerability Test)")
    print(" 4 - Analisador de Logs (Auditoria & Reporte)")
    print(" 5 - Iniciar o Servidor de Chat (Proxy Re-encryption)")
    print(" 6 - Port Knocking (Defesa por Obscuridade)")
    print(" 7 - Gestor de Passwords (Vault com 2FA)")
    print(" 0 - Sair da Aplicação")
    print("="*45)

def main():
    """
    Função principal que gere o loop de eventos e a lógica de seleção.
    
    Implementa um sistema de 'match-case' para despachar as chamadas de funções 
    especializadas de acordo com a entrada do utilizador, garantindo a 
    segregação de responsabilidades entre os módulos.
    """
    print("\nBem-vindo ao Projeto de Segurança Informática.")
    print("Desenvolvido por: Paulo Abade - 23919\n")
    
    print_menu()
    option = -1
    
    while option != 0:
        answer = input("\nEscolha uma operação: ")
        
        match answer:
            case "1":
                print("[*] A iniciar Port Scan...")
                nmap_scan()
            case "2":
                print("[*] A iniciar Stress Test (DoS)...")
                dos_attack()
            case "3":
                print("[*] A iniciar Teste de Resiliência (SYN Flood)...")
                syn_attack()
            case "4":
                print("[*] A iniciar Auditoria de Logs...")
                analyze_logs()
            case "5":
                print("[*] A iniciar Servidor de Mensagens Seguras...")
                start_server()
            case "6":
                print("[*] A executar sequência de Port Knocking...")
                knock()
            case "7":
                print("[*] A aceder ao Gestor de Credenciais...")
                password_menu()
            case "0":
                print("[!] A encerrar aplicação. Até à próxima.")
                option = 0
                break
            case _:
                print("[!] Opção inválida. Escolha um valor entre 1 e 7 ou 0 para sair.")
        
        if option != 0:
            print_menu()

if __name__ == "__main__":
    main()

