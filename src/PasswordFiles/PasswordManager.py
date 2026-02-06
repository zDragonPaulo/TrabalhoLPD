# Paulo Abade - 23919
# Mestrado de Engenharia de Segurança Informática
# Iniciado em 19/10/2025
# Última atualização: 06/02/2026
# Password Manager

import sqlite3
import pyotp
import qrcode
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# --- CONFIGURAÇÕES DE CAMINHOS ---
DB_NAME = "./PasswordFiles/passwords.db"
PRIVATE_KEY_PATH = "./PasswordFiles/private_key.pem"
PUBLIC_KEY_PATH = "./PasswordFiles/public_key.pem"
OTP_SECRET_PATH = "./PasswordFiles/otp_secret.txt"

# Garantir que a diretoria de ficheiros existe
if not os.path.exists("./PasswordFiles"):
    os.makedirs("./PasswordFiles")

def setup():
    """
    Inicializa o ambiente de segurança do gestor.
    
    Gera o par de chaves RSA se inexistente, configura o segredo TOTP para 
    o segundo fator de autenticação e cria a estrutura de tabelas no SQLite.
    O QR Code para configuração da app móvel é gerado automaticamente no primeiro setup.
    """
    if not os.path.exists(PRIVATE_KEY_PATH):
        print("[*] Configuração inicial: A gerar chaves e segredo 2FA...")
        # Gerar RSA
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(PRIVATE_KEY_PATH, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        public_key = private_key.public_key()
        with open(PUBLIC_KEY_PATH, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))

        # Gerar 2FA (TOTP)
        secret = pyotp.random_base32()
        with open(OTP_SECRET_PATH, "w") as f:
            f.write(secret)
        
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name="Paulo Abade", issuer_name="GestorDePasswords")
        qrcode.make(uri).save("./PasswordFiles/2fa_qr.png")
        print("[!] Setup concluído. Configure o 2FA lendo o ficheiro '2fa_qr.png'.")

    # Criar Tabela SQLite (Campos sensíveis como BLOB para guardar bytes cifrados)
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS credentials 
                      (id INTEGER PRIMARY KEY, url BLOB, user BLOB, password BLOB)''')
    conn.commit()
    conn.close()

def load_public_key():
    """Carrega a chave pública do disco para operações de cifragem."""
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key():
    """Carrega a chave privada do disco para operações de decifragem."""
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def encrypt_data(data):
    """
    Cifra uma string de texto limpo utilizando RSA-OAEP.
    
    Args:
        data (str): Texto a ser protegido.
    Returns:
        bytes: Dados cifrados binários.
    """
    pub_key = load_public_key()
    return pub_key.encrypt(
        data.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_data(cipher_text):
    """
    Decifra dados binários para recuperar o texto original.
    
    Args:
        cipher_text (bytes): Dados recuperados da base de dados.
    Returns:
        str: Texto limpo decifrado.
    """
    priv_key = load_private_key()
    return priv_key.decrypt(
        cipher_text,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ).decode()

def authenticate():
    """
    Valida a identidade do utilizador através de um token TOTP.
    
    Returns:
        bool: True se o código estiver correto e dentro da janela temporal.
    """
    if not os.path.exists(OTP_SECRET_PATH): return False
    with open(OTP_SECRET_PATH, "r") as f:
        secret = f.read()
    totp = pyotp.TOTP(secret)
    token = input("\n[?] Insira o código 2FA do seu dispositivo: ")
    return totp.verify(token)

def add_credential():
    """Interage com o utilizador para cifrar e guardar uma nova credencial no SQLite."""
    url = input("URL: ")
    user = input("Username: ")
    pw = input("Password: ")
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO credentials (url, user, password) VALUES (?, ?, ?)", 
                   (encrypt_data(url), encrypt_data(user), encrypt_data(pw)))
    conn.commit()
    conn.close()
    print("[+] Registo guardado com sucesso (encriptado em repouso)!")

def list_credentials():
    """Lista todas as credenciais após validação 2FA bem-sucedida."""
    if not authenticate():
        print("[!] Erro: Autenticação Multi-fator falhou.")
        return

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, url, user, password FROM credentials")
    rows = cursor.fetchall()
    
    print(f"\n{'ID':<5} | {'URL':<20} | {'User':<20} | {'Password'}")
    print("-" * 75)
    for row in rows:
        try:
            print(f"{row[0]:<5} | {decrypt_data(row[1]):<20} | {decrypt_data(row[2]):<20} | {decrypt_data(row[3])}")
        except:
            print(f"{row[0]:<5} | [Erro na decifragem do registo]")
    conn.close()

def update_credential():
    """Atualiza campos específicos de um registo após validação 2FA."""
    if not authenticate():
        print("[!] Erro: Acesso negado.")
        return

    try:
        id_register = int(input("\nID do registo a atualizar: "))
        print("1. URL | 2. Username | 3. Password | 4. Tudo")
        answer = input("Opção: ")

        conn = sqlite3.connect(DB_NAME)
        cursor = conn.cursor()

        if answer == "1":
            new_info = input("Novo URL: ")
            cursor.execute("UPDATE credentials SET url = ? WHERE id = ?", (encrypt_data(new_info), id_register))
        elif answer == "2":
            new_info = input("Novo Username: ")
            cursor.execute("UPDATE credentials SET user = ? WHERE id = ?", (encrypt_data(new_info), id_register))
        elif answer == "3":
            new_info = input("Nova Password: ")
            cursor.execute("UPDATE credentials SET password = ? WHERE id = ?", (encrypt_data(new_info), id_register))
        elif answer == "4":
            u, us, p = input("Novo URL: "), input("Novo User: "), input("Nova Pass: ")
            cursor.execute("UPDATE credentials SET url=?, user=?, password=? WHERE id=?", 
                           (encrypt_data(u), encrypt_data(us), encrypt_data(p), id_register))
        
        conn.commit()
        if cursor.rowcount > 0:
            print(f"[+] Registo {id_register} atualizado com sucesso!")
        conn.close()
    except ValueError:
        print("[!] Erro: Input inválido.")

def delete_credential():
    """Remove permanentemente um registo da base de dados após validação 2FA."""
    if not authenticate():
        print("[!] Erro: Acesso negado.")
        return

    try:
        id_register = int(input("\nID do registo a apagar: "))
        confirmar = input(f"Tem a certeza que deseja eliminar o registo {id_register}? (s/n): ")
        
        if confirmar.lower() == 's':
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM credentials WHERE id = ?", (id_register,))
            conn.commit()
            print(f"[+] Registo {id_register} eliminado.")
            conn.close()
    except ValueError:
        print("[!] Erro: ID inválido.")

def password_menu():
    """Interface principal do Gestor de Passwords."""
    setup()
    while True:
        print("\n" + "="*30)
        print("   GESTOR SEGURO DE PASSWORDS")
        print("="*30)
        print("1. Criar Registo")
        print("2. Listar Registos (Requer 2FA)")
        print("3. Atualizar Registo (Requer 2FA)")
        print("4. Eliminar Registo (Requer 2FA)")
        print("0. Sair")
        
        option = input("\nEscolha uma opção: ")
        if option == "1": add_credential()
        elif option == "2": list_credentials()
        elif option == "3": update_credential()
        elif option == "4": delete_credential()
        elif option == "0": break
        else: print("[!] Opção inválida.")

if __name__ == "__main__":
    password_menu()