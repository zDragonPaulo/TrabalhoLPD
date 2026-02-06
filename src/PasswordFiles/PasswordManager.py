# Paulo Abade - 23919
# Mestrado de Engenharia de Segurança Informática
# Iniciado em 19/10/2025
# Última atualização: 24/01/2026
# Password Manager

import sqlite3
import pyotp
import qrcode
import os
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding, rsa

# --- CONFIGURAÇÕES INICIAIS ---
DB_NAME = "./PasswordFiles/passwords.db"
PRIVATE_KEY_PATH = "./PasswordFiles/private_key.pem"
PUBLIC_KEY_PATH = "./PasswordFiles/public_key.pem"
OTP_SECRET_PATH = "./PasswordFiles/otp_secret.txt"

def setup():
    """Gera chaves e base de dados se não existirem."""
    if not os.path.exists(PRIVATE_KEY_PATH):
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

        # Gerar 2FA
        secret = pyotp.random_base32()
        with open(OTP_SECRET_PATH, "w") as f:
            f.write(secret)
        
        uri = pyotp.totp.TOTP(secret).provisioning_uri(name="Paulo Abade", issuer_name="GestorDePasswords")
        qrcode.make(uri).save("./PasswordFiles/2fa_qr.png")
        print("[!] Setup inicial concluído. QR Code gerado em '2fa_qr.png'.")

    # Criar Tabela SQLite
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS credentials 
                      (id INTEGER PRIMARY KEY, url BLOB, user BLOB, password BLOB)''')
    conn.commit()
    conn.close()

# --- FUNÇÕES DE CRIPTOGRAFIA ---
def load_public_key():
    with open(PUBLIC_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read())

def load_private_key():
    with open(PRIVATE_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(f.read(), password=None)

def encrypt_data(data):
    pub_key = load_public_key()
    return pub_key.encrypt(
        data.encode(),
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    )

def decrypt_data(cipher_text):
    priv_key = load_private_key()
    return priv_key.decrypt(
        cipher_text,
        padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
    ).decode()

# --- LÓGICA DE 2FA ---
def authenticate():
    with open(OTP_SECRET_PATH, "r") as f:
        secret = f.read()
    totp = pyotp.TOTP(secret)
    token = input("\n[?] Insira o código 2FA: ")
    return totp.verify(token)

# --- OPERAÇÕES CRUD ---
def add_credential():
    url = input("URL: ")
    user = input("Username: ")
    pw = input("Password: ")
    
    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("INSERT INTO credentials (url, user, password) VALUES (?, ?, ?)", 
                   (encrypt_data(url), encrypt_data(user), encrypt_data(pw)))
    conn.commit()
    conn.close()
    print("[+] Registo guardado com sucesso (encriptado)!")

def list_credentials():
    if not authenticate():
        print("[!] Erro: Código 2FA inválido.")
        return

    conn = sqlite3.connect(DB_NAME)
    cursor = conn.cursor()
    cursor.execute("SELECT id, url, user, password FROM credentials")
    rows = cursor.fetchall()
    
    print(f"\n{'ID':<5} | {'URL':<20} | {'User':<20} | {'Password'}")
    print("-" * 70)
    for row in rows:
        print(f"{row[0]:<5} | {decrypt_data(row[1]):<20} | {decrypt_data(row[2]):<20} | {decrypt_data(row[3])}")
    conn.close()

def update_credential():
    if not authenticate():
        print("[!] Erro: Código 2FA inválido.")
        return

    try:
        id_register = int(input("\nInsira o ID do registo que deseja atualizar: "))
        
        # O utilizador pode querer mudar apenas a password ou tudo
        print("O que deseja atualizar?")
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
        else:
            print("[!] Erro: ID não encontrado.")
        conn.close()

    except ValueError:
        print("[!] Erro: Insira um ID numérico válido.")

def delete_credential():
    if not authenticate():
        print("[!] Erro: Código 2FA inválido.")
        return

    try:
        id_register = int(input("\nInsira o ID do registo que deseja apagar: "))
        confirmar = input(f"Tem a certeza que deseja apagar o registo {id_register}? (s/n): ")
        
        if confirmar.lower() == 's':
            conn = sqlite3.connect(DB_NAME)
            cursor = conn.cursor()
            cursor.execute("DELETE FROM credentials WHERE id = ?", (id_register,))
            conn.commit()
            if cursor.rowcount > 0:
                print(f"[+] Registo {id_register} apagado com sucesso.")
            else:
                print("[!] ID não encontrado.")
            conn.close()
    except ValueError:
        print("[!] Erro: Insira um ID válido.")

def password_menu():
    setup()
    while True:
        print("\n===== Gestão de Passwords =====\n")
        print("1. Criar Registo\n")
        print("2. Listar Registos (Requer 2FA)\n")
        print("3. Atualizar Registo (Requer 2FA)\n")
        print("4. Eliminar Registo (Requer 2FA)\n")
        print("0. Sair\n")
        option = input("Escolha uma opção: ")
        if option == "1": 
            add_credential()
        elif option == "2": 
            list_credentials()
        elif option == "3":
            update_credential()
        elif option == "4":
            delete_credential()
        elif option == "0": 
            break
        else: print("Opção inválida.")
