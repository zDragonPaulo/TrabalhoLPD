# Paulo Abade - 23919
# Mestrado de Engenharia de Segurança Informática
# Iniciado em 19/10/2025
# Última atualização: 29/10/2025

# É o menu da aplicação


from AttackFiles.syn_flood_attack import syn_attack
from AttackFiles.dos_attack import dos_attack
from CheckingFiles.PortScanner import nmap_scan
from CheckingFiles.PortKnocker import knock
from PasswordFiles.PasswordManager import password_menu


# Mostra o menu da aplicação
def print_menu():
    print(" 1 - Port Checking \n 2 - DoS \n 3 - SYN Flood \n 4 - Analisar Logs \n 5 - Troca de Mensagens \n 6 - Port Knocking \n 7 - Gestor de Passwords \n 0 - Sair")

def main():
    print("Bem vindo a este projeto. \n Desenvolvido por Paulo Abade - 23919\n")
    print_menu()
    option = -1
    while(option != 0):
        answer = input("Escolha uma opção: ")

        match answer:

            case "1":
                print("Port Scan")
                nmap_scan()
            case "2":
                print("DoS")
                dos_attack()
            case "3":
                print("SYN Flood")
                syn_attack()
            case "4":
                print("Analisar Logs")
            case "5":
                print("TODO Chamar o ficheiro do Troca de Mensagens")
            case "6":
                knock()
            case "7":
                password_menu()
            case "0":
                print("Saindo..")
                option = 0
            case _:
                print("Escolha uma opção válida. Entre 1 a 7 ou 0 para sair")
        print_menu()

if __name__ == "__main__":
    main()




