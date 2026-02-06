#!/bin/bash

echo "--- A instalar dependências para o Projeto ---"

# Atualizar a lista de pacotes do sistema
sudo apt update

# Garantir que o Python3 e o PIP estão instalados
sudo apt install -y python3 python3-pip

# Instalar as bibliotecas do requirements.txt
# O --break-system-packages é necessário em versões novas do Kali/Debian
pip3 install -r requirements.txt --break-system-packages

echo "--- Instalação concluída com sucesso! ---"