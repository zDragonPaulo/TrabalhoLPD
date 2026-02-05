import socket
import os
import base64
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC


SERVER_IP = "192.168.1.86"  # IP do teu Kali
PORT = 9999
MY_USERNAME = "paulo_abade"
CLIENT_PRIV_KEY = "client_private.pem"
CLIENT_PUB_KEY = "client_public.pem"


def gerar_chaves_cliente():
    """Gera o par de chaves RSA do cliente se não existirem."""
    if not os.path.exists(CLIENT_PRIV_KEY):
        print("[*] A gerar chaves RSA do cliente...")
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        
        # Guardar Chave Privada
        with open(CLIENT_PRIV_KEY, "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        
        # Guardar Chave Pública
        public_key = private_key.public_key()
        with open(CLIENT_PUB_KEY, "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        print("[+] Chaves do Cliente criadas com sucesso.")

def get_server_public_key():
    """Handshake: Pede a chave pública ao servidor via Socket."""
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        s.connect((SERVER_IP, PORT))
        s.send("REQ_PUBKEY".encode())
        
        pub_key_data = s.recv(4096)
        s.close()
        
        temp_path = "server_temp_pub.pem"
        with open(temp_path, "wb") as f:
            f.write(pub_key_data)
        return temp_path
    except Exception as e:
        print(f"[!] Erro ao obter chave do servidor: {e}")
        return None

def encrypt_message(message, pub_key_path):
    """Cifra uma string usando a chave pública fornecida."""
    with open(pub_key_path, "rb") as f:
        pub_key = serialization.load_pem_public_key(f.read())
    
    encrypted = pub_key.encrypt(
        message.encode(),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return encrypted


def send_secure_msg():
    msg = input("\nDigite a mensagem: ")
    pub_key_path = get_server_public_key() # Cifra sempre para o servidor ler

    if pub_key_path:
        encrypted_msg = encrypt_message(msg, pub_key_path)
        
        with open(CLIENT_PUB_KEY, "rb") as f:
            my_pub_key = f.read()

        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.connect((SERVER_IP, PORT))
            header = f"SEND:{MY_USERNAME}:".encode()
            s.send(header + my_pub_key + b":MSG:" + encrypted_msg)
            s.close()
            print("[+] Mensagem enviada! O servidor guardou e associou à tua chave.")
        except Exception as e:
            print(f"[!] Erro no envio: {e}")

def decrypt_local_archive():
    """Lê o arquivo .bin e decifra usando a chave privada do cliente."""
    filename = "my_downloaded_archive.bin"
    if not os.path.exists(filename):
        print("[!] Erro: Arquivo de arquivo não encontrado.")
        return

    try:
        with open(CLIENT_PRIV_KEY, "rb") as f:
            priv_key = serialization.load_pem_private_key(f.read(), password=None)

        print(f"\n--- MENSAGENS NO ARQUIVO ({MY_USERNAME}) ---")
        with open(filename, "rb") as f:
            while True:
                size_bytes = f.read(4) # Lê o header de tamanho
                if not size_bytes: break
                
                size = int.from_bytes(size_bytes, 'big')
                encrypted_msg = f.read(size)
                
                try:
                    original = priv_key.decrypt(
                        encrypted_msg,
                        padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                    )
                    print(f"-> {original.decode()}")
                except:
                    print("-> [Mensagem ilegível: Cifrada com outra chave]")
        print("-" * 40)
    except Exception as e:
        print(f"[!] Erro ao processar arquivo: {e}")

def download_messages():
    """Descarrega o arquivo binário do servidor."""
    try:
        print(f"[*] A solicitar arquivo de {MY_USERNAME} ao servidor...")
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_IP, PORT))
        s.send(f"GET:{MY_USERNAME}".encode())
        
        data_received = b""
        while True:
            chunk = s.recv(4096)
            if not chunk: break
            data_received += chunk
        s.close()

        if data_received.startswith(b"ERRO"):
            print(f"[!] Servidor diz: {data_received.decode()}")
        else:
            with open("my_downloaded_archive.bin", "wb") as f:
                f.write(data_received)
            print("[+] Download concluído com sucesso.")
            
            ver = input("Deseja decifrar e visualizar agora? (s/n): ")
            if ver.lower() == 's':
                decrypt_local_archive()
    except Exception as e:
        print(f"[!] Erro na ligação: {e}")

def export_backup_aes():
    """Requisito: Exportação/Backup com chave simétrica."""
    password = input("Define a password para este backup: ")
    salt = b'salt_estatico_projeto'
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=32, salt=salt, iterations=100000)
    key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
    fernet = Fernet(key)
    
    texto = input("Conteúdo para backup: ")
    cifrado = fernet.encrypt(texto.encode())
    
    with open("backup_mensagens.bak", "wb") as f:
        f.write(cifrado)
    print(f"[+] Backup gerado: backup_mensagens.bak (Cifrado com AES)")
def delete_server_data():
    """Solicita ao servidor a eliminação de todas as mensagens e chaves do utilizador."""
    confirm = input(f"\n[!] Tem a certeza que deseja apagar TODAS as mensagens de '{MY_USERNAME}' no servidor? (s/n): ")
    if confirm.lower() != 's':
        return

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((SERVER_IP, PORT))
        s.send(f"DEL:{MY_USERNAME}".encode())
        
        resposta = s.recv(1024).decode()
        s.close()
        print(f"\n[SERVIDOR]: {resposta}")
        
       
            
    except Exception as e:
        print(f"[!] Erro ao solicitar eliminação: {e}")

def client_chat_menu():
    gerar_chaves_cliente()
    while True:
        print("\n" + "="*35)
        print("   ESTIG - SEGURANÇA INFORMÁTICA")
        print("       CLIENTE DE MENSAGENS")
        print("="*35)
        print("1. Enviar Mensagem Segura")
        print("2. Download e Visualizar Mensagens")
        print("3. Exportar Backup (Simétrico AES)")
        print("4. Eliminar as minhas Mensagens do Servidor")
        print("0. Sair")
        
        choice = input("\nEscolha uma opção: ")

        if choice == '1': send_secure_msg()
        elif choice == '2': download_messages()
        elif choice == '3': export_backup_aes()
        elif choice == '4': delete_server_data()
        elif choice == '0': break
        else: print("[!] Opção inválida.")

if __name__ == "__main__":
    client_chat_menu()