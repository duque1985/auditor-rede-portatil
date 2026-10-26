#!/usr/bin/env bash
# Instalador do Auditor de Rede Portátil
# Uso: sudo bash install.sh
set -euo pipefail

if [ "$(id -u)" -ne 0 ]; then
  echo "Execute com sudo: sudo bash install.sh"
  exit 1
fi

DIR="$(cd "$(dirname "$0")" && pwd)"

echo ">> Instalando dependências (nmap, python3)..."
apt-get update
apt-get install -y nmap python3 iproute2 iputils-ping

echo ">> Copiando arquivos..."
install -d /opt/auditor-rede /etc/auditor-rede /var/lib/auditor-rede
install -m 755 "$DIR/auditor.py" /opt/auditor-rede/auditor.py
[ -f /etc/auditor-rede/config.ini ] || install -m 644 "$DIR/config.exemplo.ini" /etc/auditor-rede/config.ini
install -m 644 "$DIR/auditor-rede.service" /etc/systemd/system/auditor-rede.service
ln -sf /opt/auditor-rede/auditor.py /usr/local/bin/auditor-rede

echo ">> Ativando o serviço no boot..."
systemctl daemon-reload
systemctl enable auditor-rede.service

cat <<'MSG'

Instalado com sucesso!

Próximos passos:
  1) Autorize a rede atual:   sudo auditor-rede --autorizar --nome "Minha casa"
  2) Teste uma auditoria:     sudo auditor-rede
  3) Veja o relatório:        /var/lib/auditor-rede/relatorios/ultimo_relatorio.html
  4) Configuração:            sudo nano /etc/auditor-rede/config.ini

No próximo boot, o Pi audita as redes autorizadas automaticamente.
MSG
