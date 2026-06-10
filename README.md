# ARCO — Advanced Recon & Collection for OSINT

> Herramienta de reconocimiento de dominios usando fuentes abiertas y gratuitas. Sin APIs de pago, sin dependencias innecesarias.

```
░█████╗░██████╗░░█████╗░░█████╗░
██╔══██╗██╔══██╗██╔══██╗██╔══██╗
███████║██████╔╝██║░░╚═╝██║░░██║
██╔══██║██╔══██╗██║░░██╗██║░░██║
██║░░██║██║░░██║╚█████╔╝╚█████╔╝
╚═╝░░╚═╝╚═╝░░╚═╝░╚════╝░░╚════╝
Advanced Recon & Collection for OSINT
```

---

## ¿Qué hace?

ARCO automatiza el reconocimiento pasivo y activo de dominios combinando múltiples fuentes públicas y gratuitas. Cada módulo puede ejecutarse de forma independiente o en conjunto con `full`.

---

## Instalación

```bash
git clone https://github.com/TU_USUARIO/arco.git
cd arco
pip install -r requirements.txt
```

---

## Uso

```bash
# WHOIS del dominio
python arco.py whois -d example.com

# Registros DNS + geolocalización de IPs + intento de zona transfer
python arco.py dns -d example.com

# Descubrimiento de subdominios (pasivo: crt.sh + HackerTarget + WayBack)
python arco.py subdomains -d example.com

# Subdominios pasivos + brute force con wordlist
python arco.py subdomains -d example.com --wordlist /usr/share/wordlists/subdomains.txt

# Archivos expuestos e historial en WayBack Machine (últimos 5 años)
python arco.py wayback -d example.com --years 5

# Ampliar el límite de URLs descargadas desde CDX
python arco.py wayback -d example.com --limit 50000

# Security headers, fingerprinting, robots.txt y sitemap
python arco.py headers -d example.com

# Recolección de emails (página viva + páginas archivadas)
python arco.py emails -d example.com

# Escaneo completo con reporte JSON
python arco.py full -d example.com --out ./resultados

# Escaneo completo ampliando el límite de WayBack
python arco.py full -d example.com --out ./resultados --limit 50000

# Escanear múltiples dominios desde un archivo (uno por línea, # para comentarios)
python arco.py full -D dominios.txt --out ./resultados
```

---

## Módulos

| Módulo | Descripción | Fuentes |
|---|---|---|
| `whois` | Registro WHOIS del dominio | python-whois |
| `dns` | Registros DNS + zona transfer + geoIP | dnspython, ip-api.com |
| `subdomains` | Descubrimiento pasivo + brute force opcional | crt.sh, HackerTarget, WayBack CDX |
| `wayback` | URLs indexadas, archivos expuestos, snapshot | WayBack Machine CDX API |
| `headers` | Security headers, tecnología, robots.txt, sitemap | HTTP directo |
| `emails` | Recolección de emails de páginas y archivos | HTTP + WayBack CDX |
| `full` | Todos los módulos + reporte JSON consolidado | Todos |

---

## Opciones

| Argumento | Aplica a | Descripción |
|---|---|---|
| `-d / --domain` | Todos | Dominio objetivo |
| `-D / --domain-list` | Todos | Archivo con lista de dominios (uno por línea, `#` = comentario) |
| `-o / --out` | Todos | Directorio de salida (default: `./<dominio>/`) |
| `--years N` | `wayback`, `full` | Años hacia atrás (default: 3) |
| `--limit N` | `wayback`, `full` | Máx. URLs a descargar del CDX (default: 15000) |
| `--wordlist FILE` | `subdomains`, `full` | Wordlist para brute force (opcional) |
| `--threads N` | `subdomains`, `full` | Hilos para brute force (default: 50) |
| `--no-files` | `wayback` | Omite búsqueda de archivos expuestos |
| `--no-wayback` | `emails` | No analiza páginas archivadas |

---

## Output

Cada módulo genera archivos en el directorio de salida:

```
example.com/
├── full_report.json      ← reporte consolidado
├── whois.json
├── dns.json
├── subdomains.json
├── subdomains.txt        ← un subdominio por línea
├── wayback.json
├── wayback_urls.txt      ← todas las URLs indexadas
├── wayback_files.txt     ← archivos de interés (pdf, xls, sql...)
├── headers.json
├── robots.txt
├── emails.json
└── emails.txt            ← un email por línea
```

---

## Archivos detectados por WayBack

ARCO busca automáticamente estos tipos de archivos en el historial:

`pdf` `xls` `xlsx` `doc` `docx` `ppt` `pptx` `sql` `log` `env` `config` `cfg` `bak` `backup` `zip` `tar` `gz` `rar` `json` `xml` `csv` `key` `pem` `p12`

---

## Fuentes de datos

| Fuente | Módulo | Tipo |
|---|---|---|
| [crt.sh](https://crt.sh) | subdomains | Certificate Transparency |
| [HackerTarget](https://hackertarget.com) | subdomains | DNS lookup público |
| [WayBack Machine CDX API](https://web.archive.org/cdx/) | subdomains, wayback, emails | Archivos web históricos |
| [ip-api.com](http://ip-api.com) | dns | Geolocalización de IPs |
| DNS directo | dns, subdomains | dnspython |

Todas las fuentes son **gratuitas y no requieren registro**.

---

## Notas

- **Dominio bloqueado en headers:** Si el servidor filtra por IP (geo-block, WAF, firewall), ARCO detecta la causa automáticamente y la muestra como diagnóstico.
- **Rate limit de WayBack CDX:** Si la API retorna `503` con `x-rl: 0`, significa que se alcanzó el límite de solicitudes para tu IP. Espera ~15 minutos y reintenta.
- **Emails en sitios con JavaScript:** Muchos sitios cargan correos dinámicamente. ARCO extrae emails de HTML estático, `mailto:` y páginas archivadas en WayBack. Para directorios de funcionarios de gobierno mexicano, combínalo con [GOBO](https://github.com/TU_USUARIO/gobo).

---

## Disclaimer

> ARCO es una herramienta para uso en **reconocimiento autorizado, bug bounty, CTFs e investigación de seguridad**. Úsala únicamente sobre dominios para los que tengas permiso explícito. El autor no se responsabiliza del uso indebido.

---

## Licencia

MIT — libre uso, modificación y distribución con atribución al autor original.
