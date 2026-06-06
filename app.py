from flask import Flask, render_template, request
import tldextract
import urllib.parse
import whois
import requests
import warnings
import base64
import re
from datetime import datetime

# Desabilita avisos de certificados inseguros
warnings.filterwarnings('ignore', message='Unverified HTTPS request')

app = Flask(__name__)

# --- CONFIGURAÇÕES ---
VT_API_KEY = "6e4b4ad2b96919dd87344e20097a3ae84289057493326f8a5eeab8342eb1d359"
DOMINIOS_LEGITIMOS = ["google", "microsoft", "apple", "netflix", "paypal", "itau", "amazon", "facebook", "twitter", "instagram", "linkedin"]
PALAVRAS_SUSPEITAS = ["login", "secure", "update", "verify", "account", "bank", "confirm", "payment", "password", "auth", "webscr", "transfer", "bradesco", "caixa", "santander"]
URL_SHORTENERS = ["bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly", "rebrand.ly"]
SUSPICIOUS_TLDS = ["xyz", "top", "tk", "cf", "ga", "ml", "gq", "bid", "win", "icu", "fun", "loan"]
EXTENSOES_PERIGOSAS = [".exe", ".msi", ".bat", ".cmd", ".scr", ".vbs", ".js", ".jar", ".zip", ".rar", ".7z"]

# --- FUNÇÕES DE ANÁLISE COMPLEMENTARES ---

def check_virustotal(url):
    try:
        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        api_url = f"https://www.virustotal.com/api/v3/urls/{url_id}"
        headers = {"x-apikey": VT_API_KEY}
        response = requests.get(api_url, headers=headers, timeout=5)
        
        if response.status_code == 200:
            stats = response.json()['data']['attributes']['last_analysis_stats']
            return {
                "malicious": stats.get('malicious', 0),
                "suspicious": stats.get('suspicious', 0),
                "harmless": stats.get('harmless', 0),
                "undetected": stats.get('undetected', 0)
            }
        elif response.status_code == 404:
            return "Não analisado"
    except:
        return "Erro"
    return None

def levenshtein_distance(s1, s2):
    if len(s1) < len(s2): return levenshtein_distance(s2, s1)
    if len(s2) == 0: return len(s1)
    previous_row = list(range(len(s2) + 1))
    for i, c1 in enumerate(s1):
        current_row = [i + 1]
        for j, c2 in enumerate(s2):
            insertions = previous_row[j + 1] + 1
            deletions = current_row[j] + 1
            substitutions = previous_row[j] + (c1 != c2)
            current_row.append(min(insertions, deletions, substitutions))
        previous_row = current_row
    return previous_row[-1]

def get_whois_data(url):
    try:
        ext = tldextract.extract(url)
        domain_str = f"{ext.domain}.{ext.suffix}"
        w = whois.whois(domain_str)
        
        creation = w.creation_date[0] if isinstance(w.creation_date, list) else w.creation_date
        expiration = w.expiration_date[0] if isinstance(w.expiration_date, list) else w.expiration_date
        
        return {
            "domain": domain_str,
            "registrar": w.registrar or "Desconhecido",
            "creation_date": creation.strftime('%d/%m/%Y %H:%M') if isinstance(creation, datetime) else "N/A",
            "expiration_date": expiration.strftime('%d/%m/%Y %H:%M') if isinstance(expiration, datetime) else "N/A",
            "country": w.country or "N/A",
            "emails": w.emails or "N/A"
        }
    except:
        return None

def analyze_url_behavior(url):
    reasons = []
    parsed = urllib.parse.urlparse(url)
    netloc = parsed.netloc.lower()
    path = parsed.path.lower()
    ext = tldextract.extract(url)
    domain = ext.domain.lower()

    # Extensões perigosas
    for e in EXTENSOES_PERIGOSAS:
        if path.endswith(e):
            reasons.append(f"O link aponta diretamente para um arquivo executável ou compactado perigoso ({e}).")

    # IP Direto
    if re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", netloc.split(':')[0]):
        reasons.append("A URL utiliza um endereço IP direto em vez de um nome de domínio (altamente suspeito).")

    # Encurtadores
    if any(s in netloc for s in URL_SHORTENERS):
        reasons.append("Uso de encurtador de links detectado. Isso costuma ocultar o destino final.")

    # TLD Suspeito
    if ext.suffix in SUSPICIOUS_TLDS:
        reasons.append(f"O domínio utiliza uma terminação (. {ext.suffix}) frequentemente usada para fraudes econômicas.")

    # Falta de HTTPS
    if parsed.scheme == "http":
        reasons.append("A conexão inicial usa HTTP não criptografado. Dados digitados podem ser interceptados.")

    # Typosquatting / Combosquatting
    for legit in DOMINIOS_LEGITIMOS:
        dist = levenshtein_distance(domain, legit)
        if 0 < dist <= 2:
            reasons.append(f"Possível imitação de marca (Typosquatting). O domínio é muito similar a '{legit.capitalize()}'.")

    # Palavras suspeitas no caminho
    for palavra in PALAVRAS_SUSPEITAS:
        if palavra in url.lower() and palavra != domain:
            reasons.append(f"Termo sensível voltado a engenharia social detectado na URL: '{palavra}'.")

    return reasons

# --- ROTA PRINCIPAL ---
@app.route("/", methods=["GET", "POST"])
def index():
    data = None
    if request.method == "POST":
        url_input = request.form.get("url", "").strip()
        if url_input:
            # Garante o esquema HTTP/HTTPS
            full_url = url_input if url_input.startswith(("http://", "https://")) else "https://" + url_input
            parsed_url = urllib.parse.urlparse(full_url)
            
            # Executa varreduras
            reasons = analyze_url_behavior(full_url)
            vt_result = check_virustotal(full_url)
            whois_info = get_whois_data(full_url)
            
            # API Gratuita para simular o screenshot do urlscan.io (Usa o WordPress mshots)
            screenshot_url = f"https://public-api.wordpress.com/rest/v1.1/mshots/v1/{urllib.parse.quote(full_url)}?w=800&h=600"
            
            # Nível de Risco Simples
            risk_score = 0
            if reasons: risk_score += len(reasons) * 20
            if isinstance(vt_result, dict) and vt_result['malicious'] > 0:
                risk_score += vt_result['malicious'] * 35
            risk_score = min(risk_score, 100)

            data = {
                "target_url": full_url,
                "domain": parsed_url.netloc,
                "risk_score": risk_score,
                "reasons": reasons,
                "vt": vt_result,
                "whois": whois_info,
                "screenshot": screenshot_url,
                "scan_time": datetime.now().strftime('%d/%m/%Y %H:%M:%S')
            }

    return render_template("index.html", data=data)

if __name__ == "__main__":
    app.run(debug=True, port=5000)
