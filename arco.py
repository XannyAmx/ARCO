#!/usr/bin/env python3
"""
ARCO — Advanced Recon & Collection for OSINT
Reconocimiento de dominios usando fuentes abiertas y gratuitas.
"""

import argparse, json, sys, time, re, socket, signal, threading
from datetime import datetime, timedelta
from pathlib import Path
from queue import Queue, Empty
from urllib.parse import urlparse
import urllib.request, urllib.parse

try:
    import requests
    import dns.resolver, dns.zone, dns.query, dns.exception
    import whois
    from termcolor import colored
    import tqdm
except ImportError as e:
    print(f"[!] Dependencia faltante: {e}")
    print("    pip install requests dnspython python-whois termcolor tqdm")
    sys.exit(1)

# ── Constantes ────────────────────────────────────────────────────────────────

VERSION   = "1.0.0"
UA        = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 Chrome/124.0.0.0 Safari/537.36"
CDX_URL   = "https://web.archive.org/cdx/search/cdx"
IP_API    = "http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query"

DNS_TYPES = ["A", "AAAA", "CNAME", "MX", "NS", "SOA", "TXT"]

INTERESTING_EXTS = [
    "pdf","xls","xlsx","doc","docx","ppt","pptx",
    "sql","log","env","config","cfg","bak","backup",
    "zip","tar","gz","rar","7z",
    "json","xml","csv","rtf","txt",
    "key","pem","p12","pfx",
]

SEC_HEADERS = [
    "Strict-Transport-Security",
    "Content-Security-Policy",
    "X-Frame-Options",
    "X-Content-Type-Options",
    "Referrer-Policy",
    "Permissions-Policy",
    "X-XSS-Protection",
]


# ── Utilidades ────────────────────────────────────────────────────────────────

def c(text, color, bold=False):
    return colored(text, color, attrs=["bold"] if bold else [])

def ok(msg):   print(c(f"[+] {msg}", "green"))
def info(msg): print(c(f"[*] {msg}", "cyan"))
def warn(msg): print(c(f"[!] {msg}", "yellow"))
def err(msg):  print(c(f"[x] {msg}", "red"))

def section(title):
    print(c(f"\n{'─'*62}", "magenta"))
    print(c(f"    {title}", "magenta", bold=True))
    print(c(f"{'─'*62}", "magenta"))

def banner():
    print(c(r"""
    ░█████╗░██████╗░░█████╗░░█████╗░
    ██╔══██╗██╔══██╗██╔══██╗██╔══██╗
    ███████║██████╔╝██║░░╚═╝██║░░██║
    ██╔══██║██╔══██╗██║░░██╗██║░░██║
    ██║░░██║██║░░██║╚█████╔╝╚█████╔╝
    ╚═╝░░╚═╝╚═╝░░╚═╝░╚════╝░░╚════╝
    Advanced Recon & Collection for OSINT  v""" + VERSION, "cyan", bold=True))
    print()

def ctrl_c(sig, frame):
    print(c("\n\n[!] Interrumpido.", "red"))
    sys.exit(0)
signal.signal(signal.SIGINT, ctrl_c)

def get(url, timeout=15, retries=2):
    for attempt in range(retries):
        try:
            r = requests.get(url, headers={"User-Agent": UA}, timeout=timeout,
                             allow_redirects=True, verify=True)
            return r
        except requests.exceptions.SSLError:
            try:
                import urllib3
                urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
                r = requests.get(url, headers={"User-Agent": UA}, timeout=timeout,
                                 allow_redirects=True, verify=False)
                return r
            except Exception:
                pass
        except Exception:
            if attempt < retries - 1:
                time.sleep(1)
    return None

def diagnose_connection(domain):
    """Retorna una cadena explicando por qué no se pudo conectar."""
    import socket
    try:
        ip = socket.gethostbyname(domain)
    except socket.gaierror:
        return "DNS no resuelve — dominio inexistente o sin registros A"
    # DNS OK: intentar TCP al puerto 443 y 80
    for port, proto in [(443, "HTTPS"), (80, "HTTP")]:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(5)
        try:
            s.connect((ip, port))
            s.close()
            return f"TCP {proto} ({ip}:{port}) alcanzable — posible bloqueo por User-Agent o WAF"
        except socket.timeout:
            pass
        except ConnectionRefusedError:
            pass
        finally:
            s.close()
    return (f"TCP timeout hacia {ip}:443 y {ip}:80 — el servidor bloquea esta IP "
            f"(geo-block, WAF o firewall)")

def save_json(data, path):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)

def make_outdir(domain, base="."):
    d = Path(base) / domain
    d.mkdir(parents=True, exist_ok=True)
    return d

def cdx_query(params, timeout=30):
    url = f"{CDX_URL}?{urllib.parse.urlencode(params)}"
    r = get(url, timeout=timeout)
    if not r:
        warn("WayBack CDX: sin respuesta (timeout o red caída)")
        return []
    if r.status_code == 503:
        rl = r.headers.get("x-rl", "?")
        if str(rl) == "0":
            warn("WayBack CDX: rate limit alcanzado (x-rl=0) — espera ~15 min y reintenta")
        else:
            warn("WayBack CDX: 503 Service Unavailable — API caída temporalmente")
        return []
    if r.status_code == 429:
        warn("WayBack CDX: demasiadas solicitudes (429) — espera unos minutos")
        return []
    try:
        rows = r.json()
        return rows[1:] if rows else []
    except Exception:
        return []


# ── Módulo: WHOIS ─────────────────────────────────────────────────────────────

def run_whois(domain, outdir=None):
    section("WHOIS")
    result = {"domain": domain, "data": {}}
    try:
        w = whois.whois(domain)
        data = {k: v for k, v in w.items() if v}
        result["data"] = data
        for field in ["registrar","org","country","creation_date","expiration_date",
                      "updated_date","name_servers","status","emails"]:
            val = data.get(field)
            if val:
                display = val[0] if isinstance(val, list) and len(val) == 1 else val
                ok(f"{field:<20} {str(display)[:80]}")
    except Exception as e:
        err(f"WHOIS error: {e}")
    if outdir:
        save_json(result, outdir / "whois.json")
        ok(f"→ {outdir}/whois.json")
    return result


# ── Módulo: DNS ───────────────────────────────────────────────────────────────

def run_dns(domain, outdir=None):
    section("DNS Enumeration")
    result = {"domain": domain, "records": {}, "zone_transfer": [], "ip_geo": {}}

    resolver = dns.resolver.Resolver()
    resolver.nameservers = ["8.8.8.8", "1.1.1.1", "9.9.9.9"]
    resolver.timeout = 3
    resolver.lifetime = 3

    for rtype in DNS_TYPES:
        try:
            answers = resolver.resolve(domain, rtype)
            records = [str(r) for r in answers]
            result["records"][rtype] = records
            preview = ", ".join(records[:3]) + ("..." if len(records) > 3 else "")
            ok(f"{rtype:<8} {preview}")
        except Exception:
            pass

    # Zone transfer
    info("Intentando transferencia de zona...")
    for ns in result["records"].get("NS", []):
        ns = ns.rstrip(".")
        try:
            z = dns.zone.from_xfr(dns.query.xfr(ns, domain, timeout=5))
            names = [str(n) for n in z.nodes.keys()]
            result["zone_transfer"].extend(names)
            ok(f"¡Zona transferida desde {ns}! {len(names)} registros")
        except Exception:
            pass
    if not result["zone_transfer"]:
        warn("Transferencia de zona no disponible (esperado en producción)")

    # Geolocalización de IPs
    ips = result["records"].get("A", [])
    if ips:
        info(f"Geolocalizando {len(ips)} IP(s)...")
        for ip in ips[:5]:
            r = get(IP_API.format(ip=ip), timeout=8)
            if r:
                try:
                    d = r.json()
                    if d.get("status") == "success":
                        result["ip_geo"][ip] = d
                        ok(f"{ip:<18} {d.get('country')}, {d.get('city')} | {d.get('isp')}")
                except Exception:
                    pass
            time.sleep(0.3)

    if outdir:
        save_json(result, outdir / "dns.json")
        ok(f"→ {outdir}/dns.json")
    return result


# ── Módulo: Subdominios ───────────────────────────────────────────────────────

def run_subdomains(domain, wordlist=None, threads=50, outdir=None):
    section("Subdomain Discovery")
    found = set()

    # Fuente 1: crt.sh (Certificate Transparency)
    info("crt.sh — Certificate Transparency...")
    r = get(f"https://crt.sh/?q=%.{domain}&output=json", timeout=25)
    if r:
        try:
            for entry in r.json():
                for name in entry.get("name_value", "").split("\n"):
                    name = name.strip().lstrip("*.")
                    if name.endswith(f".{domain}") or name == domain:
                        found.add(name)
            ok(f"crt.sh → {len(found)} subdominio(s)")
        except Exception:
            warn("Error parseando crt.sh")

    # Fuente 2: HackerTarget
    info("HackerTarget API...")
    prev = len(found)
    r = get(f"https://api.hackertarget.com/hostsearch/?q={domain}", timeout=15)
    if r and r.text and "error" not in r.text.lower() and "API count" not in r.text:
        for line in r.text.strip().split("\n"):
            if "," in line:
                sub = line.split(",")[0].strip()
                if sub.endswith(f".{domain}"):
                    found.add(sub)
        ok(f"HackerTarget → {len(found) - prev} nuevo(s)")
    else:
        warn("HackerTarget no disponible o límite alcanzado")

    # Fuente 3: WayBack CDX
    info("WayBack Machine CDX...")
    prev = len(found)
    rows = cdx_query({
        "url": f"*.{domain}", "output": "json", "fl": "original",
        "collapse": "urlkey", "limit": 10000
    })
    for row in rows:
        try:
            host = urlparse(row[0]).hostname or ""
            if host.endswith(f".{domain}"):
                found.add(host)
        except Exception:
            pass
    ok(f"WayBack CDX → {len(found) - prev} nuevo(s)")

    # Fuente 4: Brute force (opcional)
    if wordlist:
        info(f"Brute force con {wordlist}...")
        try:
            with open(wordlist, encoding="latin-1") as f:
                words = [w.strip() for w in f if w.strip()]
        except FileNotFoundError:
            err(f"Wordlist no encontrada: {wordlist}")
            words = []

        if words:
            lock = threading.Lock()
            bf_new = []
            q = Queue()
            for w in words:
                q.put(w)

            def worker():
                while True:
                    try:
                        word = q.get_nowait()
                    except Empty:
                        break
                    fqdn = f"{word}.{domain}"
                    try:
                        socket.setdefaulttimeout(2)
                        socket.gethostbyname(fqdn)
                        with lock:
                            if fqdn not in found:
                                found.add(fqdn)
                                bf_new.append(fqdn)
                    except Exception:
                        pass
                    finally:
                        q.task_done()

            ts = [threading.Thread(target=worker, daemon=True)
                  for _ in range(min(threads, len(words)))]
            for t in ts:
                t.start()

            with tqdm.tqdm(total=len(words), desc=c("Brute force", "magenta")) as pbar:
                done = 0
                while done < len(words):
                    current = len(words) - q.qsize()
                    pbar.update(current - done)
                    done = current
                    time.sleep(0.1)

            for t in ts:
                t.join()
            ok(f"Brute force → {len(bf_new)} nuevo(s)")

    # Resultado
    found_list = sorted(found)
    print(f"\n{c('Total subdominos únicos:', 'green', bold=True)} {len(found_list)}\n")
    for sub in found_list:
        print(f"  {c('→', 'green')} {sub}")

    result = {"domain": domain, "total": len(found_list), "subdomains": found_list}
    if outdir:
        save_json(result, outdir / "subdomains.json")
        with open(outdir / "subdomains.txt", "w") as f:
            f.write("\n".join(found_list))
        print()
        ok(f"→ {outdir}/subdomains.json y subdomains.txt")
    return result


# ── Módulo: WayBack Machine ───────────────────────────────────────────────────

def run_wayback(domain, years=3, get_files=True, url_limit=15000, outdir=None):
    section("WayBack Machine Analysis")
    result = {"domain": domain, "urls": [], "files": [], "snapshot": None}

    start = (datetime.now() - timedelta(days=365 * years)).strftime("%Y%m%d")
    end   = datetime.now().strftime("%Y%m%d")

    # Todas las URLs indexadas
    info(f"URLs indexadas en los últimos {years} año(s)...")
    rows = cdx_query({
        "url": f"*.{domain}", "output": "json",
        "fl": "original,timestamp,statuscode",
        "collapse": "urlkey",
        "from": start, "to": end, "limit": url_limit
    }, timeout=60)
    result["urls"] = [{"url": r[0], "timestamp": r[1], "status": r[2] if len(r) > 2 else ""}
                      for r in rows]
    ok(f"URLs indexadas: {len(result['urls'])}" +
       (c(f" (límite {url_limit} — usa --limit para ampliar)", "yellow") if len(result["urls"]) >= url_limit else ""))

    # Archivos de interés — filtrar localmente sobre las URLs ya descargadas
    if get_files:
        info("Buscando archivos expuestos...")
        ext_set = set(INTERESTING_EXTS)
        files = []
        by_ext = {}
        for item in result["urls"]:
            path = urlparse(item["url"]).path.lower()
            if "." not in path:
                continue
            ext = path.rsplit(".", 1)[-1][:10]
            if ext in ext_set:
                files.append({"url": item["url"], "timestamp": item["timestamp"], "ext": ext})
                by_ext.setdefault(ext, []).append(item["url"])
        result["files"] = files

        if files:
            ok(f"Archivos encontrados: {len(files)}")
            for ext, urls in sorted(by_ext.items(), key=lambda x: -len(x[1])):
                print(f"  {c(ext.upper(),'yellow'):<14} {len(urls)} archivo(s)")
        else:
            warn("No se encontraron archivos de interés en las URLs indexadas")

    # Snapshot más reciente
    info("Obteniendo snapshot más reciente...")
    rows = cdx_query({
        "url": domain, "output": "json", "fl": "timestamp",
        "limit": 1, "from": start
    })
    if rows:
        ts = rows[0][0]
        result["snapshot"] = f"https://web.archive.org/web/{ts}/{domain}"
        ok(f"Snapshot → {result['snapshot']}")

    if outdir:
        save_json(result, outdir / "wayback.json")
        if result["urls"]:
            with open(outdir / "wayback_urls.txt", "w") as f:
                f.write("\n".join(x["url"] for x in result["urls"]))
        if result["files"]:
            with open(outdir / "wayback_files.txt", "w") as f:
                f.write("\n".join(x["url"] for x in result["files"]))
        ok(f"→ {outdir}/wayback.json, wayback_urls.txt, wayback_files.txt")
    return result


# ── Módulo: Headers HTTP ──────────────────────────────────────────────────────

def run_headers(domain, outdir=None):
    section("HTTP Headers & Tech Analysis")
    result = {"domain": domain, "headers": {}, "security": {},
              "tech": [], "robots_txt": None, "sitemap": None}

    # Conectar (https primero)
    response = None
    for scheme in ["https", "http"]:
        r = get(f"{scheme}://{domain}", timeout=12)
        if r:
            response = r
            result["headers"]     = dict(r.headers)
            result["final_url"]   = str(r.url)
            result["status_code"] = r.status_code
            ok(f"Conexión → {r.status_code} | {r.url}")
            break

    if not response:
        reason = diagnose_connection(domain)
        err(f"No se pudo conectar al dominio")
        warn(f"Diagnóstico: {reason}")
        return result

    # Security headers
    print(f"\n{c('Security Headers:', 'cyan', bold=True)}")
    missing = []
    for header in SEC_HEADERS:
        val = result["headers"].get(header) or result["headers"].get(header.lower())
        if val:
            ok(f"  {header}: {str(val)[:80]}")
            result["security"][header] = {"present": True, "value": str(val)}
        else:
            warn(f"  FALTANTE: {header}")
            result["security"][header] = {"present": False}
            missing.append(header)
    if missing:
        print(f"\n  {c('Headers faltantes:', 'red')} {len(missing)}/{len(SEC_HEADERS)}")

    # Fingerprinting tecnológico
    print(f"\n{c('Tecnología detectada:', 'cyan', bold=True)}")
    tech_headers = ["Server", "X-Powered-By", "X-Generator", "X-AspNet-Version",
                    "X-Drupal-Cache", "X-Wordpress-Loaded", "Via", "X-Served-By"]
    for h in tech_headers:
        val = result["headers"].get(h) or result["headers"].get(h.lower())
        if val:
            ok(f"  {h}: {val}")
            result["tech"].append(f"{h}: {val}")
    if not result["tech"]:
        warn("  No se detectó tecnología desde headers")

    # Cookies con flags de seguridad
    print(f"\n{c('Cookies:', 'cyan', bold=True)}")
    cookies = response.cookies
    if cookies:
        for cookie in cookies:
            flags = []
            if cookie.secure:   flags.append("Secure")
            if cookie.has_nonstandard_attr("HttpOnly"): flags.append("HttpOnly")
            flag_str = ", ".join(flags) if flags else c("sin flags de seguridad", "red")
            ok(f"  {cookie.name}: {flag_str}")
            result["tech"].append(f"Cookie {cookie.name}: {flag_str}")
    else:
        info("  Sin cookies en respuesta principal")

    # robots.txt
    info("Obteniendo robots.txt...")
    r = get(f"https://{domain}/robots.txt", timeout=8)
    if r and r.status_code == 200 and len(r.text) < 50000:
        result["robots_txt"] = r.text
        disallowed = re.findall(r"(?i)Disallow:\s*(.+)", r.text)
        ok(f"robots.txt encontrado | {len(disallowed)} rutas bloqueadas")
        if disallowed:
            for d in disallowed[:8]:
                print(f"    {c('↳', 'yellow')} {d.strip()}")
            if len(disallowed) > 8:
                print(f"    {c(f'... y {len(disallowed)-8} más', 'yellow')}")

    # sitemap.xml
    info("Buscando sitemap.xml...")
    for sm in [f"https://{domain}/sitemap.xml", f"https://{domain}/sitemap_index.xml"]:
        r = get(sm, timeout=8)
        if r and r.status_code == 200 and "<" in r.text:
            result["sitemap"] = sm
            count = len(re.findall(r"<loc>", r.text))
            ok(f"Sitemap encontrado: {sm} | {count} URLs")
            break

    if outdir:
        save_json(result, outdir / "headers.json")
        if result["robots_txt"]:
            with open(outdir / "robots.txt", "w") as f:
                f.write(result["robots_txt"])
        ok(f"→ {outdir}/headers.json")
    return result


# ── Módulo: Email Harvesting ──────────────────────────────────────────────────

EMAIL_RE = re.compile(r"[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}", re.I)

def run_emails(domain, use_wayback=True, outdir=None):
    section("Email Harvesting")
    found = set()
    result = {"domain": domain, "emails": [], "domain_emails": [], "other_emails": []}

    MAILTO_RE = re.compile(r'mailto:([a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,})', re.I)

    def extract_emails(text):
        return set(e.lower() for e in EMAIL_RE.findall(text) + MAILTO_RE.findall(text))

    # Página principal + www
    info("Extrayendo emails de la página principal...")
    for target in [domain, f"www.{domain}"]:
        for scheme in ["https", "http"]:
            r = get(f"{scheme}://{target}", timeout=12)
            if r:
                emails = extract_emails(r.text)
                found.update(emails)
                if emails:
                    ok(f"{target} → {len(emails)} email(s)")
                break

    # Páginas comunes de contacto
    info("Revisando páginas de contacto...")
    for path in ["/contact", "/contacto", "/about", "/acerca", "/team", "/equipo",
                 "/directorio", "/staff", "/personal", "/funcionarios"]:
        for target in [domain, f"www.{domain}"]:
            r = get(f"https://{target}{path}", timeout=6)
            if r and r.status_code == 200:
                found.update(extract_emails(r.text))

    # WayBack Machine
    if use_wayback:
        info("Buscando emails en páginas archivadas...")

        # Priorizar páginas de contacto/directorio en el historial
        priority_keywords = ["contact", "contacto", "directorio", "staff", "about",
                             "equipo", "correo", "email", "personal", "funcionarios"]
        priority_rows = []
        for kw in priority_keywords:
            r_rows = cdx_query({
                "url": f"*.{domain}/*{kw}*", "output": "json",
                "fl": "original,timestamp", "collapse": "urlkey",
                "filter": "mimetype:text/html", "limit": 5
            })
            priority_rows.extend(r_rows)

        # Completar con muestra general
        general_rows = cdx_query({
            "url": f"*.{domain}", "output": "json",
            "fl": "original,timestamp", "collapse": "urlkey",
            "filter": "mimetype:text/html", "limit": 80
        })

        # Combinar sin duplicados: prioridad primero
        seen_urls = set()
        sample = []
        for row in priority_rows + general_rows:
            if row[0] not in seen_urls and len(sample) < 60:
                seen_urls.add(row[0])
                sample.append(row)

        if sample:
            for row in tqdm.tqdm(sample, desc=c("WayBack emails", "magenta")):
                url, ts = row[0], row[1]
                archive_url = f"https://web.archive.org/web/{ts}/{url}"
                r = get(archive_url, timeout=12)
                if r:
                    found.update(extract_emails(r.text))
                time.sleep(0.3)

        new_after_wayback = len([e for e in found if domain in e])
        if new_after_wayback == 0:
            info("No se encontraron emails en HTML — el sitio puede usar JS o mailto: obfuscado")

    # Clasificar
    domain_emails = sorted(e for e in found if domain in e)
    other_emails  = sorted(e for e in found if domain not in e)

    print(f"\n{c('Emails del dominio:', 'green', bold=True)} {len(domain_emails)}")
    for e in domain_emails:
        print(f"  {c('→', 'green')} {e}")

    if other_emails:
        print(f"\n{c('Otros emails encontrados:', 'yellow')} {len(other_emails)}")
        for e in other_emails[:15]:
            print(f"  {c('→', 'yellow')} {e}")
        if len(other_emails) > 15:
            print(f"  {c(f'... y {len(other_emails)-15} más', 'yellow')}")

    result["emails"]        = sorted(found)
    result["domain_emails"] = domain_emails
    result["other_emails"]  = other_emails

    if outdir:
        save_json(result, outdir / "emails.json")
        with open(outdir / "emails.txt", "w") as f:
            f.write("\n".join(sorted(found)))
        print()
        ok(f"→ {outdir}/emails.json y emails.txt")
    return result


# ── Full Scan ─────────────────────────────────────────────────────────────────

def run_full(domain, years=3, url_limit=15000, wordlist=None, threads=50, out=None):
    outdir = make_outdir(domain, out or ".")
    info(f"Resultados en: {outdir}/")

    report = {
        "tool": "ARCO",
        "version": VERSION,
        "domain": domain,
        "timestamp": datetime.now().isoformat(),
        "modules": {}
    }

    report["modules"]["whois"]      = run_whois(domain, outdir)
    report["modules"]["dns"]        = run_dns(domain, outdir)
    report["modules"]["subdomains"] = run_subdomains(domain, wordlist, threads, outdir)
    report["modules"]["headers"]    = run_headers(domain, outdir)
    report["modules"]["wayback"]    = run_wayback(domain, years, True, url_limit, outdir)
    report["modules"]["emails"]     = run_emails(domain, True, outdir)

    save_json(report, outdir / "full_report.json")

    section("RESUMEN FINAL")
    ok(f"Dominio          : {domain}")
    ok(f"Subdominos       : {report['modules']['subdomains']['total']}")
    ok(f"URLs en WayBack  : {len(report['modules']['wayback']['urls'])}")
    ok(f"Archivos expuestos: {len(report['modules']['wayback']['files'])}")
    ok(f"Emails           : {len(report['modules']['emails']['emails'])}")
    ok(f"Reporte completo : {outdir}/full_report.json")


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_args():
    p = argparse.ArgumentParser(
        prog="arco",
        description="ARCO — Advanced Recon & Collection for OSINT",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
módulos:
  whois        WHOIS del dominio
  dns          Registros DNS + zona transfer + geoIP
  subdomains   Descubrimiento pasivo (crt.sh, HackerTarget, WayBack) + brute force opcional
  wayback      URLs indexadas, archivos expuestos y snapshot
  headers      Security headers, fingerprinting, robots.txt y sitemap
  emails       Recolección de emails desde páginas y WayBack
  full         Ejecuta todos los módulos y genera reporte JSON

ejemplos:
  python arco.py dns -d example.com
  python arco.py subdomains -d example.com --wordlist sub.txt
  python arco.py wayback -d example.com --years 5
  python arco.py headers -d example.com
  python arco.py full -d example.com --out ./resultados
  python arco.py full -D dominios.txt --out ./resultados
        """
    )

    sub = p.add_subparsers(dest="module", required=True)

    def common(sp):
        grp = sp.add_mutually_exclusive_group(required=True)
        grp.add_argument("-d", "--domain", metavar="DOMAIN",
                         help="Dominio objetivo")
        grp.add_argument("-D", "--domain-list", metavar="FILE",
                         help="Archivo con lista de dominios (uno por línea)")
        sp.add_argument("-o", "--out", default=None, metavar="DIR",
                        help="Directorio de salida (default: ./<dominio>/)")

    sp = sub.add_parser("whois",      help="WHOIS del dominio")
    common(sp)

    sp = sub.add_parser("dns",        help="Registros DNS + geoIP")
    common(sp)

    sp = sub.add_parser("subdomains", help="Descubrimiento de subdominios")
    common(sp)
    sp.add_argument("--wordlist", metavar="FILE", help="Wordlist para brute force (opcional)")
    sp.add_argument("--threads",  type=int, default=50, help="Hilos para brute force (default: 50)")

    sp = sub.add_parser("wayback",    help="Análisis de WayBack Machine")
    common(sp)
    sp.add_argument("--years",    type=int, default=3,     help="Años hacia atrás (default: 3)")
    sp.add_argument("--limit",    type=int, default=15000, help="Máx. URLs a descargar de CDX (default: 15000)")
    sp.add_argument("--no-files", action="store_true",     help="Omite búsqueda de archivos")

    sp = sub.add_parser("headers",    help="Headers HTTP y tecnologías")
    common(sp)

    sp = sub.add_parser("emails",     help="Recolección de emails")
    common(sp)
    sp.add_argument("--no-wayback",   action="store_true", help="No analizar páginas archivadas")

    sp = sub.add_parser("full",       help="Ejecuta todos los módulos")
    common(sp)
    sp.add_argument("--years",    type=int, default=3,     help="Años hacia atrás (default: 3)")
    sp.add_argument("--limit",    type=int, default=15000, help="Máx. URLs CDX (default: 15000)")
    sp.add_argument("--wordlist", metavar="FILE",          help="Wordlist para brute force (opcional)")
    sp.add_argument("--threads",  type=int, default=50,    help="Hilos para brute force (default: 50)")

    return p.parse_args()


def clean_domain(raw):
    d = raw.strip().lower()
    for prefix in ("https://", "http://"):
        if d.startswith(prefix):
            d = d[len(prefix):]
    return d.rstrip("/")


def load_domains(args):
    """Retorna lista de dominios limpios desde -d o -D."""
    if args.domain:
        return [clean_domain(args.domain)]
    try:
        with open(args.domain_list, encoding="utf-8") as f:
            domains = [
                clean_domain(line)
                for line in f
                if line.strip() and not line.startswith("#")
            ]
        if not domains:
            err(f"El archivo '{args.domain_list}' está vacío o solo tiene comentarios")
            sys.exit(1)
        return domains
    except FileNotFoundError:
        err(f"Archivo no encontrado: {args.domain_list}")
        sys.exit(1)


def run_module(args, domain):
    outdir = make_outdir(domain, args.out or ".") if args.out else None

    if   args.module == "whois":
        run_whois(domain, outdir)
    elif args.module == "dns":
        run_dns(domain, outdir)
    elif args.module == "subdomains":
        run_subdomains(domain, getattr(args, "wordlist", None),
                       getattr(args, "threads", 50), outdir)
    elif args.module == "wayback":
        run_wayback(domain, args.years, not args.no_files, args.limit, outdir)
    elif args.module == "headers":
        run_headers(domain, outdir)
    elif args.module == "emails":
        run_emails(domain, not args.no_wayback, outdir)
    elif args.module == "full":
        run_full(domain, args.years, getattr(args, "limit", 15000),
                 getattr(args, "wordlist", None), getattr(args, "threads", 50), args.out)


def main():
    banner()
    args = build_args()

    domains = load_domains(args)

    if len(domains) > 1:
        print(c(f"[*] {len(domains)} dominios cargados desde '{args.domain_list}'", "cyan"))

    for i, domain in enumerate(domains, 1):
        if len(domains) > 1:
            print(c(f"\n{'═'*62}", "blue"))
            print(c(f"  [{i}/{len(domains)}] {domain}", "blue", bold=True))
            print(c(f"{'═'*62}", "blue"))
        run_module(args, domain)

    print(c(f"\n  [✓] Happy OSINT ;)\n", "cyan", bold=True))


if __name__ == "__main__":
    main()
