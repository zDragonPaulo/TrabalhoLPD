import socket
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes


MSG_FOLDER = "server_messages"
CLIENT_KEYS_FOLDER = "client_keys"
PUB_KEY_FILE = "public_key.pem"
PRIV_KEY_FILE = "private_key.pem"

# Criar pastas necessárias
for folder in [MSG_FOLDER, CLIENT_KEYS_FOLDER]:
    if not os.path.exists(folder): os.makedirs(folder)

def decrypt_blob(encrypted_blob):
    """Decifra usando a chave privada do servidor."""
    try:
        with open(PRIV_KEY_FILE, "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        
        plain_text = private_key.decrypt(
            encrypted_blob,
            padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
        )
        return plain_text # Retorna bytes
    except Exception as e:
        print(f"[!] Erro na decriptação: {e}")
        return None

def save_message(user, encrypted_blob):
    filename = os.path.join(MSG_FOLDER, f"{user}_archive.bin")
    with open(filename, "ab") as f:
        f.write(len(encrypted_blob).to_bytes(4, 'big'))
        f.write(encrypted_blob)

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.bind(('0.0.0.0', 9999))
    server.listen(5)
    print("\n[+] Servidor 'Re-Encryption' ativo na porta 9999...")

    while True:
        client, addr = server.accept()
        try:
            data = client.recv(16384) # Buffer maior para suportar a chave pública no meio
            if not data: continue

            msg_decoded = data.decode('utf-8', errors='ignore')

            # --- COMANDO: PEDIDO DE CHAVE PÚBLICA DO SERVER ---
            if msg_decoded.startswith("REQ_PUBKEY"):
                with open(PUB_KEY_FILE, "rb") as f:
                    client.send(f.read())
                print(f"[*] Chave pública enviada para {addr}")

            # --- COMANDO: ENVIO (SEND:user:pubkey:MSG:blob) ---
            elif msg_decoded.startswith("SEND:"):
                try:
                    # Formato: SEND:user:PUBKEY_DATA:MSG:ENCRYPTED_BLOB
                    parts = data.split(b':', 2)
                    user = parts[1].decode()
                    sub_parts = parts[2].split(b':MSG:', 1)
                    
                    client_pub_key_data = sub_parts[0]
                    encrypted_blob = sub_parts[1]

                    # 1. Guardar/Atualizar chave pública do cliente
                    with open(os.path.join(CLIENT_KEYS_FOLDER, f"{user}.pub"), "wb") as f:
                        f.write(client_pub_key_data)

                    # 2. Guardar mensagem
                    save_message(user, encrypted_blob)
                    
                    # 3. Mostrar no ecrã do servidor (Decifrado com Privada do Server)
                    conteudo = decrypt_blob(encrypted_blob)
                    if conteudo:
                        print(f"\n[MENSAGEM DE {user}]: {conteudo.decode('utf-8')}")
                except:
                    print("[!] Erro ao processar pacote SEND.")
            elif msg_decoded.startswith("DEL:"):
                user = msg_decoded.split(":")[1].strip()
                msg_path = os.path.join(MSG_FOLDER, f"{user}_archive.bin")
                key_path = os.path.join(CLIENT_KEYS_FOLDER, f"{user}.pub")
                
                removido = False
                for p in [msg_path, key_path]:
                    if os.path.exists(p):
                        os.remove(p)
                        removido = True
                
                if removido:
                    client.send(f"SUCESSO: Todos os dados de {user} foram eliminados.".encode())
                    print(f"[-] Dados do utilizador {user} eliminados a pedido do cliente.")
                else:
                    client.send("ERRO: Nenhum dado encontrado para eliminar.".encode())
            # --- COMANDO: DOWNLOAD COM RE-CIFRAGEM (GET:user) ---
            elif msg_decoded.startswith("GET:"):
                user = msg_decoded.split(":")[1].strip()
                filename = os.path.join(MSG_FOLDER, f"{user}_archive.bin")
                pub_client_path = os.path.join(CLIENT_KEYS_FOLDER, f"{user}.pub")

                if os.path.exists(filename) and os.path.exists(pub_client_path):
                    print(f"[*] A re-cifrar arquivo para {user}...")
                    
                    # Carregar chave pública do cliente
                    with open(pub_client_path, "rb") as f:
                        client_pub_key = serialization.load_pem_public_key(f.read())
                    
                    re_encrypted_archive = b""
                    with open(filename, "rb") as f:
                        while True:
                            size_bytes = f.read(4)
                            if not size_bytes: break
                            size = int.from_bytes(size_bytes, 'big')
                            blob_server = f.read(size)
                            
                            # Decifra com a chave do SERVIDOR
                            raw_msg = decrypt_blob(blob_server)
                            
                            # Volta a cifrar com a chave do CLIENTE
                            blob_client = client_pub_key.encrypt(
                                raw_msg,
                                padding.OAEP(mgf=padding.MGF1(hashes.SHA256()), algorithm=hashes.SHA256(), label=None)
                            )
                            re_encrypted_archive += len(blob_client).to_bytes(4, 'big') + blob_client
                    
                    client.sendall(re_encrypted_archive)
                else:
                    client.send(b"ERRO:Arquivo ou Chave nao encontrados")

        except Exception as e:
            print(f"[!] Erro: {e}")
        finally:
            client.close()

def gerar_chaves():
    if not os.path.exists(PRIV_KEY_FILE):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        with open(PRIV_KEY_FILE, "wb") as f:
            f.write(private_key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption()))
        with open(PUB_KEY_FILE, "wb") as f:
            f.write(private_key.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo))
        print("[+] Chaves do Servidor geradas.")

if __name__ == "__main__":
    gerar_chaves()
    start_server()