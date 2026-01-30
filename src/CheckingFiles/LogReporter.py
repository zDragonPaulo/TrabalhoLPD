# Paulo Abade - 23919
# Mestrado de Engenharia de Segurança Informática
# Iniciado em 19/10/2025
# Última atualização: 30/01/2026
# Log Reporter

# Foi necessário instalar o rsyslog, e ativar o apache2


import re
import geoip2.database
import os
from fpdf import FPDF
import csv
from datetime import datetime
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
    data_to_pdf = []
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
                    ts, ip = match.group(1).replace('T', ' '), match.group(2)
                    country, city = get_ip_info(ip)
                    print(f"[{ts}] SSH Fail: {ip} ({country}, {city})")
                    data_to_pdf.append((ts, ip, country, city, "SSH Login Failed"))

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
                    ip, raw_ts, code = match.group(1), match.group(2), match.group(3)
                    ts = format_http_date(raw_ts) # Para ficar igual à data do SSH
                    country, city = get_ip_info(ip)
                    print(f"[{ts}] HTTP {code}: {ip} ({country}, {city})")
                    data_to_pdf.append((ts, ip, country, city, f"HTTP Error {code}"))
    want_a_report = input("Deseja um relatório em PDF e em CSV? (s/n)")
    if want_a_report.lower() == "s":
        data_to_pdf.sort(key=lambda x: x[0])
        generate_pdf_report(data_to_pdf)
        generate_csv_report(data_to_pdf)
class LogReport(FPDF):
    def header(self):
        self.set_font("Arial", "B", 15)
        self.cell(0, 10, "Relatório de Segurança - Análise de Logs", ln=True, align="C")
        self.set_font("Arial", "I", 10)
        self.cell(0, 10, f"Gerado em: {datetime.now().strftime('%d/%m/%Y %H:%M:%S')}", ln=True, align="C")
        self.ln(10)

    def footer(self):
        self.set_y(-15)
        self.set_font("Arial", "I", 8)
        self.cell(0, 10, f"Página {self.page_no()}", align="C")

def generate_pdf_report(data_list, filename="Relatorio_Logs.pdf"):
    pdf = LogReport()
    pdf.add_page()
    pdf.set_font("Courier", size=9) # Fonte monoespaçada fica melhor para logs
    
    # Cabeçalho da Tabela
    pdf.set_fill_color(200, 200, 200)
    pdf.cell(40, 8, "Timestamp", border=1, fill=True)
    pdf.cell(35, 8, "IP", border=1, fill=True)
    pdf.cell(35, 8, "País", border=1, fill=True)
    pdf.cell(35, 8, "Cidade", border=1, fill=True)
    pdf.cell(45, 8, "Detalhes", border=1, fill=True, ln=True)

    # Dados
    pdf.set_fill_color(255, 255, 255)
    for item in data_list:
        # item deve ser um dicionário ou tuplo: (ts, ip, country, city, detail)
        pdf.cell(40, 7, str(item[0]), border=1)
        pdf.cell(35, 7, str(item[1]), border=1)
        pdf.cell(35, 7, str(item[2]), border=1)
        pdf.cell(35, 7, str(item[3]), border=1)
        pdf.cell(45, 7, str(item[4]), border=1, ln=True)

    pdf.output(filename)
    print(f"\n[+] PDF gerado com sucesso: {filename}")


def format_http_date(date_str):
    try:
        # O formato do Apache é: 24/Jan/2026:19:17:02 +0000
        # O %z trata o fuso horário (+0000)
        dt = datetime.strptime(date_str, "%d/%b/%Y:%H:%M:%S %z")
        # Retorna no formato ISO: 2026-01-24 19:17:02
        return dt.strftime("%Y-%m-%d %H:%M:%S")
    except Exception:
        # Se falhar por algum motivo, retorna a string original limpa (sem o fuso)
        return date_str.split(' ')[0]

def generate_csv_report(data_list, filename="relatorio_ataques.csv"):
    # data_list: [(ts, ip, country, city, detail), ...]
    headers = ['Timestamp', 'IP', 'Pais', 'Cidade', 'Evento']
    
    try:
        with open(filename, mode='w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f, delimiter=';') # Ponto e vírgula é melhor para o Excel em PT
            writer.writerow(headers)
            writer.writerows(data_list)
        print(f"[+] CSV gerado com sucesso: {filename}")
    except Exception as e:
        print(f"[!] Erro ao gerar CSV: {e}")