#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Auditor de Rede Portátil — Raspberry Pi

Liga o Pi numa rede, descobre os dispositivos, procura portas e serviços
de risco, gera um relatório em HTML/JSON e (opcionalmente) desliga sozinho.

Use SOMENTE em redes suas ou com autorização por escrito do responsável.
"""

import argparse
import configparser
import datetime
import html
import ipaddress
import json
import os
import re
import shutil
import subprocess
import sys
import time
import urllib.request
import xml.etree.ElementTree as ET
from pathlib import Path

VERSAO = "1.0.0"

CONFIG_PATH = Path(os.environ.get("AUDITOR_CONFIG", "/etc/auditor-rede/config.ini"))
DIR_DADOS = Path(os.environ.get("AUDITOR_DADOS", "/var/lib/auditor-rede"))
ARQ_AUTORIZADAS = DIR_DADOS / "redes_autorizadas.json"
DIR_ESTADO = DIR_DADOS / "estado"
DIR_RELATORIOS_PADRAO = DIR_DADOS / "relatorios"
DIRS_BOOT = [Path("/boot/firmware"), Path("/boot")]

CONFIG_PADRAO = {
    "perfil": "padrao",
    "desligar_ao_final": "nao",
    "aguardar_rede_segundos": "90",
    "pasta_saida": "",
    "pasta_copia": "",
    "ntfy_topico": "",
}

# Perfis de escaneamento (argumentos extras do nmap)
PERFIS = {
    "rapido": ["--top-ports", "100", "-T4"],
    "padrao": ["--top-ports", "100", "-sV", "--version-light", "-T4"],
    "completo": ["--top-ports", "1000", "-sV", "--version-light", "-T4"],
}

NIVEIS = {"alto": 3, "medio": 2, "baixo": 1, "info": 0, "ok": -1}
ROTULO = {"alto": "Alto", "medio": "Médio", "baixo": "Baixo", "info": "Info", "ok": "OK"}

# porta -> (nível, título, recomendação)
REGRAS_PORTA = {
    23: ("alto", "Telnet aberto", "O Telnet trafega senhas sem criptografia. Desative ou troque por SSH."),
    2323: ("alto", "Telnet aberto", "O Telnet trafega senhas sem criptografia. Desative ou troque por SSH."),
    5900: ("alto", "VNC aberto", "Acesso remoto de tela exposto na rede. Use senha forte e, de preferência, acesso por VPN."),
    5901: ("alto", "VNC aberto", "Acesso remoto de tela exposto na rede. Use senha forte e, de preferência, acesso por VPN."),
    5555: ("alto", "ADB (Android) aberto", "Pode permitir controle total do aparelho. Desative a depuração por rede."),
    512: ("alto", "Serviço legado (rexec/rlogin/rsh) aberto", "Protocolos antigos e inseguros. Desative."),
    513: ("alto", "Serviço legado (rexec/rlogin/rsh) aberto", "Protocolos antigos e inseguros. Desative."),
    514: ("alto", "Serviço legado (rexec/rlogin/rsh) aberto", "Protocolos antigos e inseguros. Desative."),
    6379: ("alto", "Redis exposto", "Costuma rodar sem senha. Restrinja o acesso e ative autenticação."),
    27017: ("alto", "MongoDB exposto", "Banco sem autenticação é risco grave. Restrinja o acesso e ative autenticação."),
    9200: ("alto", "Elasticsearch exposto", "Costuma rodar sem autenticação. Restrinja o acesso."),
    11211: ("alto", "Memcached exposto", "Sem autenticação por padrão. Restrinja o acesso."),
    3389: ("medio", "Área de Trabalho Remota (RDP) aberta", "Alvo frequente de ataques. Use senha forte, NLA e acesso por VPN."),
    21: ("medio", "FTP aberto", "O FTP não criptografa. Prefira SFTP e confira se o login anônimo está desativado."),
    111: ("medio", "rpcbind/NFS exposto", "Confirme que só máquinas autorizadas acessam."),
    2049: ("medio", "rpcbind/NFS exposto", "Confirme que só máquinas autorizadas acessam."),
    3306: ("medio", "Banco de dados acessível na rede", "Libere apenas para quem precisa e use senhas fortes."),
    5432: ("medio", "Banco de dados acessível na rede", "Libere apenas para quem precisa e use senhas fortes."),
    1433: ("medio", "Banco de dados acessível na rede", "Libere apenas para quem precisa e use senhas fortes."),
    1521: ("medio", "Banco de dados acessível na rede", "Libere apenas para quem precisa e use senhas fortes."),
    554: ("medio", "Vídeo (RTSP) aberto — câmera/DVR", "Confira se a senha padrão foi trocada e se o firmware está atualizado."),
    37777: ("medio", "Gerenciamento de DVR/câmera aberto", "Equipamentos assim são alvo comum de botnets. Troque a senha padrão e atualize."),
    34567: ("medio", "Gerenciamento de DVR/câmera aberto", "Equipamentos assim são alvo comum de botnets. Troque a senha padrão e atualize."),
    1883: ("medio", "MQTT sem criptografia", "Dados de IoT trafegam em texto puro. Use TLS e autenticação."),
    8291: ("medio", "Winbox (MikroTik) aberto", "Mantenha o firmware atualizado e limite o acesso a IPs confiáveis."),
    7547: ("medio", "TR-069 aberto", "Gerenciamento remoto do provedor. Não deveria ficar acessível na rede local."),
    445: ("baixo", "Compartilhamento de arquivos (SMB)", "Confirme quem tem acesso e que o SMBv1 está desativado."),
    139: ("baixo", "NetBIOS aberto", "Legado do Windows. Desative se não for usar."),
    22: ("baixo", "SSH ativo", "Confirme senha forte ou chave e desative o login direto do root."),
    9100: ("baixo", "Impressora com porta RAW aberta", "Qualquer pessoa da rede pode imprimir. Avalie restringir."),
}
PORTAS_HTTP = {80, 8000, 8008, 8080, 8888}
PORTAS_HTTPS = {443, 8443}


# --------------------------------------------------------------------------
# Utilidades
# --------------------------------------------------------------------------

def log(msg):
    print(f"[{datetime.datetime.now():%H:%M:%S}] {msg}", flush=True)


def agora_iso():
    return datetime.datetime.now().isoformat(timespec="seconds")


def executar(cmd, timeout=None):
    return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)


def ler_json(caminho, padrao):
    try:
        return json.loads(Path(caminho).read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return padrao


def salvar_json(caminho, dados):
    caminho = Path(caminho)
    caminho.parent.mkdir(parents=True, exist_ok=True)
    caminho.write_text(json.dumps(dados, ensure_ascii=False, indent=2), encoding="utf-8")


def carregar_config():
    cfg = dict(CONFIG_PADRAO)
    if CONFIG_PATH.exists():
        cp = configparser.ConfigParser()
        try:
            cp.read(CONFIG_PATH, encoding="utf-8")
            if cp.has_section("auditor"):
                cfg.update({k: v.strip() for k, v in cp["auditor"].items()})
        except configparser.Error as e:
            log(f"Aviso: não consegui ler {CONFIG_PATH}: {e}")
    return cfg


def eh_sim(valor):
    return str(valor).strip().lower() in ("sim", "s", "yes", "y", "true", "1")


def arquivo_boot(nome):
    for d in DIRS_BOOT:
        p = d / nome
        if p.exists():
            return p
    return None


def led(modo):
    """Controla o LED verde do Pi (heartbeat = trabalhando, default-on = terminou, timer = erro)."""
    for nome in ("ACT", "led0"):
        base = Path("/sys/class/leds") / nome
        if base.exists():
            try:
                (base / "trigger").write_text(modo)
            except OSError:
                pass
            return


def notificar(topico, titulo, mensagem):
    if not topico:
        return
    try:
        req = urllib.request.Request(
            f"https://ntfy.sh/{topico}",
            data=mensagem.encode("utf-8"),
            headers={"Title": titulo},
        )
        urllib.request.urlopen(req, timeout=10).read()
        log("Notificação enviada pelo ntfy.")
    except Exception as e:  # sem internet etc.
        log(f"Não foi possível enviar a notificação: {e}")


# --------------------------------------------------------------------------
# Rede
# --------------------------------------------------------------------------

def rede_atual():
    r = executar(["ip", "-4", "route", "show", "default"])
    m = re.search(r"default via (\S+) dev (\S+)", r.stdout)
    if not m:
        return None
    gateway, iface = m.group(1), m.group(2)
    r = executar(["ip", "-4", "-o", "addr", "show", "dev", iface, "scope", "global"])
    m = re.search(r"inet (\S+)", r.stdout)
    if not m:
        return None
    ifc = ipaddress.ip_interface(m.group(1))
    rede = ifc.network
    if rede.prefixlen < 22:  # evita varrer redes enormes (ex.: /8)
        rede = ipaddress.ip_network(f"{ifc.ip}/24", strict=False)
    return {"interface": iface, "ip": str(ifc.ip), "cidr": str(rede), "gateway": gateway}


def mac_do_gateway(gateway):
    executar(["ping", "-c", "1", "-W", "1", gateway])
    r = executar(["ip", "neigh", "show", gateway])
    m = re.search(r"lladdr ([0-9a-fA-F:]{17})", r.stdout)
    return m.group(1).upper() if m else ""


def mac_proprio(iface):
    try:
        return Path(f"/sys/class/net/{iface}/address").read_text().strip().upper()
    except OSError:
        return ""


def completar_rede(rede):
    rede["mac_gateway"] = mac_do_gateway(rede["gateway"])
    rede["id"] = re.sub(r"[^0-9A-Za-z]+", "_", f"{rede['cidr']}_{rede['mac_gateway']}").strip("_")
    return rede


def aguardar_rede(segundos):
    fim = time.time() + segundos
    while time.time() < fim:
        r = rede_atual()
        if r:
            return r
        time.sleep(3)
    return None


def aguardar_hora(segundos=20):
    fim = time.time() + segundos
    while time.time() < fim:
        r = executar(["timedatectl", "show", "-p", "NTPSynchronized", "--value"])
        if r.stdout.strip() == "yes":
            return True
        time.sleep(2)
    return False


# --------------------------------------------------------------------------
# Escaneamento
# --------------------------------------------------------------------------

def novo_host(ip):
    return {
        "ip": ip, "mac": "", "fabricante": "", "nome": "", "portas": [],
        "alertas": [], "gateway": False, "proprio": False, "novo": False,
    }


def parse_xml(texto):
    hosts = {}
    try:
        raiz = ET.fromstring(texto)
    except ET.ParseError:
        return hosts
    for h in raiz.findall("host"):
        st = h.find("status")
        if st is None or st.get("state") != "up":
            continue
        ip = ""
        mac = ""
        fab = ""
        for a in h.findall("address"):
            if a.get("addrtype") == "ipv4":
                ip = a.get("addr", "")
            elif a.get("addrtype") == "mac":
                mac = a.get("addr", "").upper()
                fab = a.get("vendor", "")
        if not ip:
            continue
        item = novo_host(ip)
        item["mac"], item["fabricante"] = mac, fab
        hn = h.find("hostnames/hostname")
        if hn is not None:
            item["nome"] = hn.get("name", "")
        for p in h.findall("ports/port"):
            est = p.find("state")
            if est is None or est.get("state") != "open":
                continue
            sv = p.find("service")
            servico = sv.get("name", "") if sv is not None else ""
            produto = ""
            if sv is not None:
                produto = " ".join(x for x in (sv.get("product", ""), sv.get("version", "")) if x)
            item["portas"].append({
                "porta": int(p.get("portid")),
                "proto": p.get("protocol", "tcp"),
                "servico": servico,
                "produto": produto,
            })
        hosts[ip] = item
    return hosts


def escanear(rede, perfil):
    meu_ip = rede["ip"]
    log(f"Etapa 1/2: descobrindo dispositivos em {rede['cidr']}...")
    r = executar(["nmap", "-sn", "-oX", "-", rede["cidr"]], timeout=900)
    vivos = parse_xml(r.stdout)
    if meu_ip not in vivos:
        vivos[meu_ip] = novo_host(meu_ip)
    log(f"{len(vivos)} dispositivo(s) encontrado(s).")

    ips = sorted(vivos, key=ipaddress.ip_address)
    log(f"Etapa 2/2: verificando portas e serviços (perfil: {perfil})...")
    cmd = ["nmap", "-Pn", "--open", "--host-timeout", "90s", "--max-retries", "2",
           "-oX", "-"] + PERFIS[perfil] + ips
    r = executar(cmd, timeout=3600)
    for ip, h in parse_xml(r.stdout).items():
        if ip in vivos:
            vivos[ip]["portas"] = h["portas"]
            for campo in ("mac", "fabricante", "nome"):
                if not vivos[ip][campo]:
                    vivos[ip][campo] = h[campo]

    for ip, h in vivos.items():
        h["gateway"] = ip == rede["gateway"]
        h["proprio"] = ip == meu_ip
        if h["proprio"] and not h["mac"]:
            h["mac"] = mac_proprio(rede["interface"])
    return sorted(vivos.values(), key=lambda x: ipaddress.ip_address(x["ip"]))


# --------------------------------------------------------------------------
# Análise de risco e histórico
# --------------------------------------------------------------------------

def avaliar(h):
    alertas = []
    vistos = set()
    abertas = {p["porta"] for p in h["portas"]}
    for p in h["portas"]:
        regra = REGRAS_PORTA.get(p["porta"])
        if regra and regra[1] not in vistos:
            vistos.add(regra[1])
            nivel, titulo, detalhe = regra
            alertas.append({"nivel": nivel, "titulo": f"{titulo} (porta {p['porta']})", "detalhe": detalhe})
    if abertas & PORTAS_HTTP and not abertas & PORTAS_HTTPS:
        if h["gateway"]:
            alertas.append({
                "nivel": "medio",
                "titulo": "Painel do roteador acessível por HTTP (sem criptografia)",
                "detalhe": "Confira se a senha padrão foi trocada e se o acesso remoto pela internet está desativado.",
            })
        else:
            alertas.append({
                "nivel": "baixo",
                "titulo": "Interface web sem HTTPS",
                "detalhe": "Se for um painel de administração, use senha forte e troque a senha de fábrica.",
            })
    if h["mac"] and not h["fabricante"] and not h["proprio"]:
        alertas.append({
            "nivel": "info",
            "titulo": "Fabricante não identificado",
            "detalhe": "Celulares modernos usam MAC privado, então é comum. Se não reconhece o aparelho, investigue.",
        })
    return alertas


def chave(h):
    return h["mac"] or f"ip:{h['ip']}"


def comparar(rede_id, hosts):
    arq = DIR_ESTADO / f"{rede_id}.json"
    anterior = ler_json(arq, None)
    atuais = {chave(h): {"ip": h["ip"], "nome": h["nome"], "fabricante": h["fabricante"]} for h in hosts}
    primeira = anterior is None
    sumiram = []
    if not primeira:
        antes = anterior.get("dispositivos", {})
        for h in hosts:
            if chave(h) not in antes:
                h["novo"] = True
        sumiram = [v for k, v in antes.items() if k not in atuais]
    salvar_json(arq, {"data": agora_iso(), "dispositivos": atuais})
    return primeira, sumiram


# --------------------------------------------------------------------------
# Relatório
# --------------------------------------------------------------------------

CSS = """
:root{--bg:#f5f6f8;--card:#fff;--txt:#1c2127;--mut:#5d6975;--bd:#dde1e6;
--alto:#c62828;--medio:#e65100;--baixo:#1565c0;--info:#607d8b;--ok:#2e7d32;--bt:#fff}
@media (prefers-color-scheme: dark){:root{--bg:#13171b;--card:#1c2228;--txt:#e7ebef;--mut:#98a5b1;
--bd:#2c353e;--alto:#ef5350;--medio:#ffa726;--baixo:#64b5f6;--info:#90a4ae;--ok:#66bb6a;--bt:#111}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--txt);font:15px/1.5 system-ui,-apple-system,Segoe UI,Roboto,sans-serif}
main{max-width:1100px;margin:0 auto;padding:24px 16px 48px}
h1{font-size:1.5rem;margin:0 0 4px}h2{font-size:1.15rem;margin:32px 0 10px}
.mut{color:var(--mut);font-size:.9rem}
.cards{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:10px;margin-top:18px}
.card{background:var(--card);border:1px solid var(--bd);border-radius:10px;padding:14px}
.num{font-size:1.9rem;font-weight:700;line-height:1.1}.rot{color:var(--mut);font-size:.85rem}
.c-alto{color:var(--alto)}.c-medio{color:var(--medio)}.c-baixo{color:var(--baixo)}
.tw{overflow-x:auto;background:var(--card);border:1px solid var(--bd);border-radius:10px}
table{border-collapse:collapse;width:100%;min-width:640px}
th,td{text-align:left;padding:9px 12px;border-bottom:1px solid var(--bd);vertical-align:top}
th{font-size:.8rem;color:var(--mut);text-transform:uppercase;letter-spacing:.04em}
tr:last-child td{border-bottom:0}
.badge{display:inline-block;padding:1px 9px;border-radius:99px;font-size:.78rem;font-weight:600;color:var(--bt)}
.b-alto{background:var(--alto)}.b-medio{background:var(--medio)}.b-baixo{background:var(--baixo)}
.b-info{background:var(--info)}.b-ok{background:var(--ok)}
.tag{display:inline-block;border:1px solid var(--bd);border-radius:6px;padding:0 6px;margin-left:6px;font-size:.75rem;color:var(--mut)}
.tag-novo{border-color:var(--medio);color:var(--medio)}
.aviso{background:var(--card);border-left:4px solid var(--medio);padding:10px 14px;border-radius:6px}
footer{margin-top:36px;color:var(--mut);font-size:.82rem}
"""


def rotulo_host(h):
    return h["nome"] or h["fabricante"] or "Dispositivo sem nome"


def badge(nivel):
    return f'<span class="badge b-{nivel}">{ROTULO[nivel]}</span>'


def gerar_html(c):
    esc = html.escape
    rede, res = c["rede"], c["resumo"]
    novos_txt = "—" if c["primeira"] else str(res["novos"])
    cartoes = [
        ("Dispositivos", res["dispositivos"], "n"),
        ("Alertas altos", res["alto"], "alto"),
        ("Alertas médios", res["medio"], "medio"),
        ("Alertas baixos", res["baixo"], "baixo"),
        ("Novos desde a última vez", novos_txt, "n"),
    ]
    html_cartoes = "".join(
        f'<div class="card"><div class="num c-{cls}">{val}</div><div class="rot">{rot}</div></div>'
        for rot, val, cls in cartoes
    )

    lista = []
    for h in c["hosts"]:
        for a in h["alertas"]:
            lista.append((NIVEIS[a["nivel"]], h, a))
    lista.sort(key=lambda t: (-t[0], ipaddress.ip_address(t[1]["ip"])))
    linhas_alertas = "".join(
        f'<tr><td>{badge(a["nivel"])}</td>'
        f'<td>{esc(rotulo_host(h))}<br><span class="mut">{esc(h["ip"])}</span></td>'
        f'<td><strong>{esc(a["titulo"])}</strong><br><span class="mut">{esc(a["detalhe"])}</span></td></tr>'
        for _, h, a in lista
    ) or '<tr><td colspan="3">Nenhum alerta encontrado.</td></tr>'

    linhas_hosts = []
    for h in c["hosts"]:
        tags = ""
        if h["gateway"]:
            tags += '<span class="tag">Roteador/gateway</span>'
        if h["proprio"]:
            tags += '<span class="tag">Este Pi</span>'
        if h["novo"]:
            tags += '<span class="tag tag-novo">Novo</span>'
        portas = ", ".join(
            f'{p["porta"]}/{esc(p["servico"] or "?")}' for p in h["portas"]
        ) or "—"
        nivel = max((a["nivel"] for a in h["alertas"]), key=lambda n: NIVEIS[n], default="ok")
        fab = esc(h["fabricante"]) if h["fabricante"] else "—"
        linhas_hosts.append(
            f'<tr><td>{esc(h["ip"])}</td>'
            f'<td>{esc(rotulo_host(h))}{tags}<br><span class="mut">{fab} · {esc(h["mac"] or "sem MAC")}</span></td>'
            f'<td>{portas}</td><td>{badge(nivel)}</td></tr>'
        )

    sumiram = ""
    if c["sumiram"]:
        itens = "".join(
            f'<li>{esc(s.get("nome") or s.get("fabricante") or "Dispositivo")} ({esc(s.get("ip", ""))})</li>'
            for s in c["sumiram"]
        )
        sumiram = f'<h2>Não apareceram desta vez</h2><ul>{itens}</ul>'

    aviso = "" if c["hora_ok"] else (
        '<p class="aviso">Atenção: o relógio do Pi pode estar desatualizado '
        '(sem sincronização de hora pela internet).</p>'
    )

    return f"""<!doctype html>
<html lang="pt-BR"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Auditoria de rede — {esc(rede['cidr'])}</title>
<style>{CSS}</style></head><body><main>
<h1>Auditoria de rede</h1>
<div class="mut">{esc(c['data'])} · rede {esc(rede['cidr'])} · gateway {esc(rede['gateway'])} ·
interface {esc(rede['interface'])} · perfil {esc(c['perfil'])} · duração {esc(c['duracao'])}</div>
{aviso}
<div class="cards">{html_cartoes}</div>
<h2>Alertas</h2>
<div class="tw"><table><thead><tr><th>Nível</th><th>Dispositivo</th><th>Problema e recomendação</th></tr></thead>
<tbody>{linhas_alertas}</tbody></table></div>
<h2>Dispositivos</h2>
<div class="tw"><table><thead><tr><th>IP</th><th>Dispositivo</th><th>Portas abertas</th><th>Risco</th></tr></thead>
<tbody>{''.join(linhas_hosts)}</tbody></table></div>
{sumiram}
<footer>Gerado pelo Auditor de Rede Portátil v{VERSAO}. Este relatório contém informações sensíveis
da rede: guarde com cuidado e use somente em redes autorizadas.</footer>
</main></body></html>"""


def salvar_relatorios(contexto, cfg):
    pasta = Path(cfg["pasta_saida"]) if cfg["pasta_saida"] else DIR_RELATORIOS_PADRAO
    pasta.mkdir(parents=True, exist_ok=True)
    base = f"auditoria_{datetime.datetime.now():%Y%m%d_%H%M%S}_{re.sub(r'[^0-9A-Za-z]+', '-', contexto['rede']['cidr'])}"
    arq_html, arq_json = pasta / f"{base}.html", pasta / f"{base}.json"
    arq_html.write_text(gerar_html(contexto), encoding="utf-8")
    salvar_json(arq_json, contexto)
    shutil.copy2(arq_html, pasta / "ultimo_relatorio.html")
    log(f"Relatório salvo em {arq_html}")
    if cfg["pasta_copia"]:
        try:
            destino = Path(cfg["pasta_copia"])
            destino.mkdir(parents=True, exist_ok=True)
            for a in (arq_html, arq_json):
                shutil.copy2(a, destino / a.name)
            log(f"Cópia salva em {destino}")
        except OSError as e:
            log(f"Não consegui copiar para {cfg['pasta_copia']}: {e}")
    return arq_html


# --------------------------------------------------------------------------
# Fluxo principal
# --------------------------------------------------------------------------

def autorizar(rede, nome):
    aut = ler_json(ARQ_AUTORIZADAS, {})
    aut[rede["id"]] = {
        "nome": nome or rede["cidr"],
        "cidr": rede["cidr"],
        "gateway_mac": rede["mac_gateway"],
        "autorizada_em": agora_iso(),
    }
    salvar_json(ARQ_AUTORIZADAS, aut)


def listar():
    aut = ler_json(ARQ_AUTORIZADAS, {})
    if not aut:
        print("Nenhuma rede autorizada ainda. Use: sudo auditor-rede --autorizar --nome \"Minha rede\"")
        return
    for k, v in aut.items():
        print(f"- {v.get('nome')}  [{v.get('cidr')}  gateway {v.get('gateway_mac') or '?'}]  desde {v.get('autorizada_em')}")


def auditar(args, cfg):
    hora_ok = True
    if args.boot:
        try:
            espera = int(cfg["aguardar_rede_segundos"])
        except ValueError:
            espera = 90
        log("Aguardando a rede...")
        rede = aguardar_rede(espera)
        if rede:
            hora_ok = aguardar_hora(20)
    else:
        rede = rede_atual()
    if not rede:
        log("Sem rede disponível (nenhuma rota padrão). Nada a fazer.")
        return 2
    rede = completar_rede(rede)
    log(f"Rede: {rede['cidr']} · gateway {rede['gateway']} · interface {rede['interface']}")

    marcador = arquivo_boot("autorizar-rede.txt") if args.boot else None
    if marcador:
        try:
            nome = marcador.read_text(encoding="utf-8").strip().splitlines()[0]
        except (OSError, IndexError):
            nome = ""
        autorizar(rede, nome)
        try:
            marcador.unlink()
        except OSError:
            pass
        log("Rede autorizada pelo arquivo autorizar-rede.txt (arquivo removido).")

    if rede["id"] not in ler_json(ARQ_AUTORIZADAS, {}):
        if args.boot or not sys.stdin.isatty():
            log("Rede NÃO autorizada. Escaneamento cancelado. Veja o README para autorizar.")
            return 3
        print(f"\nA rede {rede['cidr']} não está na lista de redes autorizadas.")
        resp = input("Você tem autorização do responsável para auditá-la? Digite SIM para continuar: ")
        if resp.strip().upper() != "SIM":
            log("Cancelado.")
            return 3

    perfil = args.perfil or cfg["perfil"]
    if perfil not in PERFIS:
        perfil = "padrao"

    inicio = time.time()
    hosts = escanear(rede, perfil)
    for h in hosts:
        h["alertas"] = avaliar(h)
    primeira, sumiram = comparar(rede["id"], hosts)
    for h in hosts:
        if h["novo"]:
            h["alertas"].append({
                "nivel": "medio",
                "titulo": "Dispositivo novo na rede",
                "detalhe": "Não estava na auditoria anterior. Confirme se você o reconhece.",
            })

    resumo = {"dispositivos": len(hosts), "alto": 0, "medio": 0, "baixo": 0, "info": 0,
              "novos": sum(1 for h in hosts if h["novo"])}
    for h in hosts:
        for a in h["alertas"]:
            resumo[a["nivel"]] += 1

    seg = int(time.time() - inicio)
    contexto = {
        "versao": VERSAO,
        "data": datetime.datetime.now().strftime("%d/%m/%Y %H:%M"),
        "duracao": f"{seg // 60} min {seg % 60} s",
        "perfil": perfil,
        "hora_ok": hora_ok,
        "rede": {k: rede[k] for k in ("interface", "ip", "cidr", "gateway", "mac_gateway")},
        "primeira": primeira,
        "resumo": resumo,
        "sumiram": sumiram,
        "hosts": hosts,
    }
    salvar_relatorios(contexto, cfg)
    log(f"Concluído: {resumo['dispositivos']} dispositivos, "
        f"{resumo['alto']} alertas altos, {resumo['medio']} médios, {resumo['baixo']} baixos.")
    notificar(
        cfg["ntfy_topico"], "Auditor de rede - concluido",
        f"Rede {rede['cidr']}: {resumo['dispositivos']} dispositivos, "
        f"{resumo['alto']} altos, {resumo['medio']} medios, {resumo['baixo']} baixos.",
    )
    return 0


def main():
    ap = argparse.ArgumentParser(description="Auditor de Rede Portátil (use apenas em redes autorizadas).")
    ap.add_argument("--boot", action="store_true", help="modo automático (usado pelo serviço no boot)")
    ap.add_argument("--autorizar", action="store_true", help="autoriza a rede atual")
    ap.add_argument("--nome", default="", help="nome da rede ao autorizar (ex.: Oficina)")
    ap.add_argument("--listar", action="store_true", help="lista as redes autorizadas")
    ap.add_argument("--perfil", choices=list(PERFIS), help="rapido, padrao ou completo")
    ap.add_argument("--desligar", action="store_true", help="desliga o Pi ao terminar")
    ap.add_argument("--versao", action="version", version=f"auditor-rede {VERSAO}")
    args = ap.parse_args()

    if os.geteuid() != 0:
        print("Execute como administrador: sudo auditor-rede")
        return 1
    cfg = carregar_config()

    if args.listar:
        listar()
        return 0
    if args.autorizar:
        rede = rede_atual()
        if not rede:
            print("Sem rede disponível.")
            return 2
        rede = completar_rede(rede)
        autorizar(rede, args.nome)
        print(f"Rede {rede['cidr']} autorizada como \"{args.nome or rede['cidr']}\".")
        return 0
    if not shutil.which("nmap"):
        print("nmap não encontrado. Rode o install.sh ou: sudo apt install nmap")
        return 1

    desligar = args.desligar or (args.boot and eh_sim(cfg["desligar_ao_final"]))
    led("heartbeat")
    try:
        codigo = auditar(args, cfg)
    except Exception as e:
        log(f"Erro inesperado: {e}")
        codigo = 1
    led("default-on" if codigo == 0 else "timer")

    if desligar:
        if arquivo_boot("manter-ligado.txt"):
            log("Arquivo manter-ligado.txt encontrado: o Pi NÃO será desligado.")
        else:
            log("Desligando em 1 minuto (cancele com: sudo shutdown -c).")
            executar(["shutdown", "-h", "+1", "Auditor de rede concluído"])
    return codigo


if __name__ == "__main__":
    sys.exit(main())
