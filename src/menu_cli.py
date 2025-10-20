from AttackFiles.syn_flood_attack import syn_attack




print("Bem vindo a este projeto. \n Desenvolvido por Paulo Abade - 23919\n")
def main():
    print(" 1 - Port Checking \n 2 - DoS \n 3 - SYN Flood \n 4 - Analisar Logs \n 5 - Troca de Mensagens \n 6 - Port Knocking \n 7 - Gestor de Passwords \n 0 - Sair")
    option = -1
    while(option != 0):
        answer = input("Escolha uma opção: ")

        match answer:

            case "1":
                print("Portchecking")
            case "2":
                print("DoS")
            case "3":
                print("SYN Flood")
                syn_attack()
            case "4":
                print("Analisar Logs")
            case "5":
                print("TODO Chamar o ficheiro do Troca de Mensagens")
            case "6":
                print("TODO Chamar o ficheiro do PortKnocking")
            case "7":
                print("TODO Chamar o ficheiro do Gestor de Passwords")
            case "0":
                print("Saindo..")
                option = 0
            case _:
                print("Escolha uma opção válida. Entre 1 a 7 ou 0 para sair")
    # Start again

if __name__ == "__main__":
    main()




