# 🔎 ReconCraft — Guia Prático de Recon & One-Liners (2025)

> Projeto em PT com foco **técnico e limpo** para acelerar hunting em bug bounties e pentests.  
> Objetivo: consolidar **ferramentas ativas/maintained** e **one-liners** modernos para **recon**, **enumeração**, e **detecção rápida** (XSS, SQLi, SSTI, SSRF, etc.).  
---

## Sumário

- [Stack de Ferramentas](#stack-de-ferramentas)
- [Instalação Rápida](#instalação-rápida)
- [Atalhos de Shell](#atalhos-de-shell)
- [Playbooks & One-Liners](#playbooks--one-liners)
  - [Escopo & Coleta Inicial](#escopo--coleta-inicial)
  - [Subdomínios & Resolução](#subdomínios--resolução)
  - [Probing HTTP & Screenshot](#probing-http--screenshot)
  - [Crawling & JavaScript](#crawling--javascript)
  - [Segredos & Endpoints em JS](#segredos--endpoints-em-js)
  - [Descoberta de Parâmetros](#descoberta-de-parâmetros)
  - [XSS (Reflected/DOM/Blind)](#xss-reflecteddomblind)
  - [SSTI](#ssti)
  - [SQLi](#sqli)
  - [Open Redirect](#open-redirect)
  - [SSRF](#ssrf)
  - [CORS](#cors)
  - [Prototype Pollution (Client-side)](#prototype-pollution-client-side)
  - [Bruteforce de Diretórios](#bruteforce-de-diretórios)
  - [Exposição de .git](#exposição-de-git)
  - [Shodan / ASN / DNS Passivo](#shodan--asn--dns-passivo)
  - [Mass Scan com Nuclei](#mass-scan-com-nuclei)
  - [Distribuído com Axiom](#distribuído-com-axiom)
- [Boas Práticas](#boas-práticas)
- [Licença](#licença)

---

## Stack de Ferramentas

> Conjunto curado e amplamente usado em 2024/2025.

**Recon/Enumeração**
- Amass, Subfinder, Findomain, Chaos (ProjectDiscovery), ShuffleDNS, MassDNS, dnsx
- dnsgen, hakrevdns, haktldextract, HEDnsExtractor

**Probing/Scanning**
- httpx, naabu, nuclei, xray, jaeles, dalfox, xsstrike, kxss, wingman

**Crawling/Coleta**
- katana, hakrawler, gospider, subjs, getJS, LinkFinder

**URLs & Arquivos**
- gau, waybackurls, urldedupe, unfurl, anew/unew, anti-burl, tojson

**Segredos e Git**
- SecretFinder, gitleaks, goop

**Descoberta de Parâmetros**
- x8, arjun, paramspider

**Fuzz/Wordlists/Paralelo**
- ffuf, dirsearch, haklistgen, rush, gargs, interlace

**Infra & Automação**
- axiom, notify

**OSINT/Plataformas**
- shodan cli, recon.dev (API), crt.sh, JLDC/Anubis

---

## Instalação Rápida

```bash
# Go (recomendado)
sudo apt update && sudo apt install -y golang jq python3-pip git make

# ProjectDiscovery e afins (exemplos)
go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest
go install -v github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
go install -v github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
go install -v github.com/projectdiscovery/katana/cmd/katana@latest
go install -v github.com/tomnomnom/assetfinder@latest
go install -v github.com/tomnomnom/anew@latest
go install -v github.com/tomnomnom/waybackurls@latest
go install -v github.com/lc/gau/v2/cmd/gau@latest
go install -v github.com/jaeles-project/gospider@latest
go install -v github.com/projectdiscovery/dnsx/cmd/dnsx@latest
go install -v github.com/ProjectAnte/dnsgen@latest

# Python deps (ex.: LinkFinder, SecretFinder)
pip3 install uro
git clone https://github.com/GerbenJavado/LinkFinder && cd LinkFinder && pip3 install -r requirements.txt && cd ..
git clone https://github.com/m4ll0k/SecretFinder && cd SecretFinder && pip3 install -r requirements.txt && cd ..
````

---

## Atalhos de Shell

```bash
# ~/.bashrc ou ~/.zshrc

# JS vivos via gau + anti-burl
reconjs() {
  gau -subs "$1" | grep -Ei '\.js$' | grep -Eiv '(\.jsp|\.json)' > /tmp/js_$$.txt
  cat /tmp/js_$$.txt | anti-burl | awk '{print $4}' | sort -u > AliveJs.txt
  rm -f /tmp/js_$$.txt
}

# Subdomínios via crt.sh
certsubs() {
  curl -s "https://crt.sh/?q=%25.$1&output=json" | jq -r '.[].name_value' | sed 's/\*\.//g' | sort -u
}

# Subdomínios via JLDC/Anubis
anubis() {
  curl -s "https://jldc.me/anubis/subdomains/$1" | grep -Po '((http|https):\/\/)?(([\w\.-]*)\.([\w]*)\.([A-Za-z]))\w+' | sort -u
}
```

---

## Playbooks & One-Liners

### Escopo & Coleta Inicial

```bash
# Importar escopo no BBRF (ex.: DoD)
bbrf inscope add '*.af.mil' '*.army.mil' '*.navy.mil' '*.uscg.mil' '*.osd.mil' '*.disa.mil' '*.health.mil'
```

### Subdomínios & Resolução

```bash
# Passivo + certs + anubis -> resolver -> vivos
{ subfinder -d target.com -all -silent
  certsubs target.com
  anubis target.com
} | anew subs.txt

cat subs.txt | dnsx -a -resp-only -silent | awk -F, '{print $1}' | anew resolved.txt
httpx -l resolved.txt -silent -threads 200 -status-code -title -follow-redirects | tee alive.txt
```

### Probing HTTP & Screenshot

```bash
# Titles/Códigos/Tecnologias
httpx -l resolved.txt -silent -threads 200 -status-code -title -tech-detect > http_profile.txt

# Screenshots (GoWitness)
cat resolved.txt | xargs -I@ gowitness single @
```

### Crawling & JavaScript

```bash
# Katana profundidade 5 (filtrando JS/JSON)
cat alive.txt | awk '{print $1}' | katana -d 5 -em js,json -silent | anew js_json.txt

# Hakrawler profundidade 3
cat alive.txt | awk '{print $1}' | rush -j100 'hakrawler -plain -depth 3 -url {}' | anew endpoints.txt
```

### Segredos & Endpoints em JS

```bash
# Extrair endpoints de JS
xargs -a js_json.txt -P8 -I@ bash -c 'echo -e "\n[JS]: @"; python3 LinkFinder/linkfinder.py -i @ -o cli' | anew js_endpoints.txt

# Segredos (keys/tokens) em JS
xargs -a js_json.txt -P8 -I@ python3 SecretFinder/SecretFinder.py -i @ -o cli | anew js_secrets.txt
```

### Descoberta de Parâmetros

```bash
# x8 — GET params ocultos
cat alive.txt | awk '{print $1}' | sed 's/$/\//' | xargs -I@ sh -c 'x8 -u @ -w params.txt -o enumerate'

# Arjun — GET/POST params
arjun -i <(awk '{print $1}' alive.txt) -t 50 -o arjun_results.json
```

### XSS (Reflected/DOM/Blind)

```bash
# Dalfox rápido
cat <(gau target.com) | dalfox pipe --multicast -o xss_report.txt

# KXSS (reflexões)
echo "https://testphp.vulnweb.com" | waybackurls | kxss

# Wingman (headless) + notify
cat subs.txt | xargs -I@ -P5 sh -c 'wingman -u @ --crawl | notify'
```

### SSTI

```bash
# Injetar {{7*7}} em URLs arquivadas e observar retornos
waybackurls https://target.com | qsreplace "{{7*7}}" | ffuf -u FUZZ -w - -ac -mc all -fs 0
```

### SQLi

```bash
# Padrões gf + sqlmap em massa
httpx -l resolved.txt -silent | waybackurls | gf sqli | anew sqli.txt
sqlmap -m sqli.txt --batch --random-agent --level 1
```

### Open Redirect

```bash
export LHOST="https://evil.example"
gau target.com | gf redirect | qsreplace "$LHOST" | \
xargs -I% -P25 sh -c 'curl -Is "%" | grep -q "Location: $LHOST" && echo "[OpenRedirect] %"'
```

### SSRF

```bash
# Substitui valores de parâmetros por um domínio colaborador
findomain -t target.com -q | httpx -silent | gau | grep "=" | \
qsreplace "http://<colab-id>.oast.site"
```

### CORS

```bash
assetfinder -subs-only target.com | httpx -silent | \
rush -j200 'curl -sk -I -H "Origin: http://evil.com" {} | grep -qi "Access-Control-Allow-Origin: http://evil.com" && echo "[CORS] {}"'
```

### Prototype Pollution (Client-side)

```bash
cat alive.txt | awk '{print $1"/?__proto__[pwn]=poc"}' | \
page-fetch --javascript 'window.pwn==="poc" ? "[VULN]" : ""' | grep VULN
```

### Bruteforce de Diretórios

```bash
# ffuf multi-host + paths
ffuf -w <(awk '{print $1}' alive.txt):DOMAIN -w paths.txt:PATH -u DOMAIN/PATH -t 100 -mc 200,204,301,302,403 -fs 0
```

### Exposição de .git

```bash
sed 's/$/\/.git\/HEAD/' subs.txt | httpx -silent -status-code -mc 200,301,302 -threads 300 -location
```

### Shodan / ASN / DNS Passivo

```bash
# Shodan -> httpx -> nuclei
shodan search 'hostname:"target.com"' --fields ip_str,port | sed 's/ /:/' > shodan_hosts.txt
httpx -l shodan_hosts.txt -silent | nuclei -severity high,critical -o shodan_nuclei.txt

# ASN -> IPs -> Reverse DNS
echo "ORG NAME" | metabigor net --org -v | awk '{print $3}' | \
xargs -I@ sh -c 'prips @ | hakrevdns -r 1.1.1.1' | awk '{print $2}' | sed 's/\.$//' | anew rev_hosts.txt
```

### Mass Scan com Nuclei

```bash
# Atualize templates antes
nuclei -update
httpx -l resolved.txt -silent -threads 200 -o live_urls.txt
nuclei -l live_urls.txt -severity low,medium,high,critical -c 100 -o nuclei_report.txt
```

### Distribuído com Axiom

```bash
# Pipeline típico
axiom-scan subs.txt -m httpx -o live.txt
axiom-scan live.txt -m nuclei -t ~/nuclei-templates/ -o ax_nuclei.txt
```

---

## Boas Práticas

* **Respeite escopo e rate-limit** dos programas; use `-rate`/`-c`/`-t` moderados.
* **Centralize artefatos** (URLs, endpoints, segredos) e gere relatórios reproduzíveis.
* **Valide achados manualmente** (reduz falso-positivo e melhora qualidade do reporte).
* **Automatize notificações** com `notify` (Slack, Discord, e-mail).
* **Atualize ferramentas/templates** (ex.: `nuclei -update`, versões `@latest`).

---

## Licença

Este guia é distribuído “as is”. Utilize apenas com **autorização** e em conformidade com **leis** e **políticas** de cada programa.

```
```
