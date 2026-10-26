# Auditor de Rede Portátil (Raspberry Pi 3b)

Um Raspberry Pi que você liga em uma rede, e ele "descobre os dispositivos, procura portas e serviços de risco, gera um relatório em HTML e se desliga sozinho". Não depende do roteador e não precisa ficar ligado o tempo todo.

> ⚠️ *Uso responsável:* utilize somente em redes *suas* ou com *autorização por escrito* do responsável. Escanear redes de terceiros sem permissão pode ser crime. O projeto tem uma trava de segurança: só audita redes previamente autorizadas.

# Como funciona

Liga o Pi na rede (cabo ou Wi-Fi)
        ↓
Detecta a rede e confere se ela está autorizada
        ↓
Etapa 1: descobre os dispositivos (nmap)
Etapa 2: verifica portas e serviços abertos
        ↓
Analisa riscos e compara com a auditoria anterior
        ↓
Salva o relatório (HTML + JSON) → avisa no celular (opcional) → desliga

# O que o relatório mostra

- Todos os dispositivos conectados (IP, nome, MAC, fabricante).
- Portas abertas e serviços de cada aparelho.
- Alertas por nível (Alto, Médio, Baixo, Info), com recomendação de correção. Exemplos: Telnet aberto, VNC, RDP, DVR/câmera, banco de dados exposto, painel do roteador sem HTTPS.
- Dispositivos **novos** desde a última auditoria e os que **não apareceram** desta vez.

Veja um exemplo (dados fictícios) em [`exemplo-relatorio.html`](exemplo-relatorio.html).

# Requisitos

- Raspberry Pi 3B ou superior, com Raspberry Pi OS (Lite serve).
- Cartão SD, fonte de energia confiável e cabo de rede (recomendado) ou Wi-Fi já configurado.
- Internet apenas para instalar (e, opcionalmente, para a notificação).

# Instalação

No Pi, conectado à internet:

bash
git clone https://github.com/duque1985/auditor-rede-portatil.git
cd auditor-rede-portatil
sudo bash install.sh

# Primeiro uso

*1. Autorize a rede atual* (a trava de segurança):

bash
sudo auditor-rede --autorizar --nome "Minha casa"

*2. Rode uma auditoria de teste:*

bash
sudo auditor-rede

*3. Abra o relatório:* `/var/lib/auditor-rede/relatorios/ultimo_relatorio.html`

*4. Ative o modo automático:* o serviço já fica habilitado. Reinicie o Pi (`sudo reboot`) e ele audita sozinho no boot.

# Autorizar uma rede sem acesso ao terminal (sem tela/SSH)

Com o cartão SD no computador, crie na partição de boot (`bootfs`) um arquivo chamado `autorizar-rede.txt` e escreva o nome da rede na primeira linha (ex.: `Cliente Fulano`). No próximo boot, o Pi autoriza a rede em que estiver conectado e apaga o arquivo. Faça isso **somente** com autorização do responsável pela rede.

# Modo "liga, escaneia e desliga"

Edite `/etc/auditor-rede/config.ini` e troque para:

ini
desligar_ao_final = sim

Ao terminar, o Pi avisa e desliga em 1 minuto (cancele com `sudo shutdown -c`). Para *impedir* o desligamento numa vez específica (manutenção), crie um arquivo vazio `manter-ligado.txt` na partição de boot do cartão.

> Dica: teste primeiro com `desligar_ao_final = nao` até confirmar que tudo funciona.

# Configuração

Arquivo: `/etc/auditor-rede/config.ini` (modelo em [`config.exemplo.ini`](config.exemplo.ini))

| Opção | Para que serve |
|---|---|
| `perfil` | `rapido`, `padrao` (recomendado) ou `completo` |
| `desligar_ao_final` | `sim`/`nao`: desliga o Pi após o escaneamento no boot |
| `aguardar_rede_segundos` | tempo de espera pela rede antes de desistir |
| `pasta_saida` | onde salvar os relatórios (padrão: `/var/lib/auditor-rede/relatorios`) |
| `pasta_copia` | cópia extra dos relatórios (pendrive/HD montado) |
| `ntfy_topico` | tópico do [ntfy.sh](https://ntfy.sh) para aviso no celular ao terminar |

# Como pegar o relatório depois

- *Pendrive/HD:* aponte `pasta_copia` para a pasta do dispositivo montado.
- *Samba:* aponte `pasta_saida` para uma pasta compartilhada e acesse da rede.
- *SSH/Tailscale:* `scp usuario@IP-DO-PI:/var/lib/auditor-rede/relatorios/ultimo_relatorio.html .`
- *Cartão SD:* retire o cartão e leia no computador (pasta `/var/lib/auditor-rede/relatorios`).

# Sinais do LED verde do Pi

| LED | Significado |
|---|---|
| Pulsando (batimento) | auditoria em andamento |
| Aceso fixo | terminou com sucesso |
| Piscando em intervalos regulares | erro, rede não autorizada ou sem rede |

# Comandos úteis

bash
sudo auditor-rede                    # auditoria manual (pede confirmação se a rede não for autorizada)
sudo auditor-rede --perfil completo  # mais portas e mais lento
sudo auditor-rede --listar           # redes autorizadas
sudo auditor-rede --desligar         # desliga o Pi ao terminar
journalctl -u auditor-rede -b        # log da execução no último boot

# Limitações

- Mostra o que está *visível e aberto* na rede. Não explora vulnerabilidades nem testa senhas.
- Celulares modernos usam MAC privado, então podem aparecer como "novos" ao trocar de rede.
- Sem internet, o relógio do Pi pode ficar errado (o relatório avisa).
- Redes maiores que /22 são limitadas a /24 para evitar varreduras gigantes.

# Estrutura do projeto

auditor.py             # script principal (Python, sem dependências extras)
install.sh             # instalador
auditor-rede.service   # serviço systemd (roda no boot)
config.exemplo.ini     # configuração de exemplo
exemplo-relatorio.html # exemplo de relatório com dados fictícios

# Ideias para evoluir

- Verificação de senhas padrão em câmeras e roteadores (somente em equipamentos próprios).
- Escaneamento de portas UDP (SNMP, UPnP).
- Relatório em PDF e histórico comparativo entre auditorias.
- Envio do relatório por e-mail ou Telegram.

# Aviso legal

Este projeto é educacional e destinado a auditorias *autorizadas*. O autor não se responsabiliza pelo uso indevido da ferramenta.
