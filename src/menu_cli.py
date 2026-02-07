# Paulo Abade - 23919
# Mestrado de Engenharia de Segurança Informática
# Iniciado em 19/10/2025
# Última atualização: 06/02/2026

# É o menu da aplicação



from AttackFiles.syn_flood_attack import syn_attack
from AttackFiles.dos_attack import dos_attack
from CheckingFiles.PortScanner import nmap_scan
from CheckingFiles.PortKnocker import knock
from CheckingFiles.LogReporter import analyze_logs
from PasswordFiles.PasswordManager import password_menu
from ChatFiles.server_chat import start_server

def print_menu():
    """
    Exibe a interface gráfica textual (CLI) com as opções disponíveis.
    """
 
    print("="*45)
    print(" 1 - Port Checking")
    print(" 2 - DoS")
    print(" 3 - SYN Flood")
    print(" 4 - Analisar Logs")
    print(" 5 - Iniciar o Servidor de Chat")
    print(" 6 - Port Knocking")
    print(" 7 - Gestor de Passwords")
    print(" 0 - Sair")
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

