# Paulo Abade - 23919
# Mestrado de Engenharia de Segurança Informática
# Iniciado em 19/10/2025
# Última atualização: 24/01/2026
# Log Reporter

# Foi necessário instalar o rsyslog, e ativar o apache2


import re
import geoip2.database
import os

# Caminho para a base de dados 
GEOIP_DB_PATH = './CheckingFiles/GeoLite2-City.mmdb'

def get_ip_info(ip):
    try:
        if not os.path.exists(GEOIP_DB_PATH):
            return "DB não encontrada", "N/A"
        
        with geoip2.database.Reader(GEOIP_DB_PATH) as reader:
            response = reader.city(ip)
            country = response.country.name if response.country.name else "Desconhecido"
            city = response.city.name if response.city.name else "Desconhecida"
            return country, city
    except Exception:
        return "Interno/Inválido", "N/A"

def analyze_logs():
    print("\n--- Analisador de Logs (SSH & HTTP) ---")
    
    # 1. Analisar SSH (Debian/Ubuntu/Kali: /var/log/auth.log)
    ssh_log = "/var/log/auth.log"
    if os.path.exists(ssh_log):
        print(f"\n[+] Analisando SSH: {ssh_log}")
        # Regex para capturar data e IP de falhas de login
        ssh_pattern = r"^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}).*Failed password for .* from (\d+\.\d+\.\d+\.\d+)"
        
        with open(ssh_log, "r") as f:
            for line in f:
                match = re.search(ssh_pattern, line)
                if match:
                    ts, ip = match.group(1), match.group(2)
                    country, city = get_ip_info(ip)
                    print(f"[{ts}] SSH Fail: {ip} ({country}, {city})")
    else:
        print("[!] Log de SSH não encontrado ou sem permissão.")

    # 2. Analisar HTTP (Apache: /var/log/apache2/access.log)
    http_log = "/var/log/apache2/access.log"
    if os.path.exists(http_log):
        print(f"\n[+] Analisando HTTP: {http_log}")
        http_pattern = r"^(\d+\.\d+\.\d+\.\d+).*\[(.*?)\] \".*?\" (401|403|404)"
        
        with open(http_log, "r") as f:
            for line in f:
                match = re.search(http_pattern, line)
                if match:
                    ip, ts, code = match.group(1), match.group(2), match.group(3)
                    country, city = get_ip_info(ip)
                    print(f"[{ts}] HTTP {code}: {ip} ({country}, {city})")

