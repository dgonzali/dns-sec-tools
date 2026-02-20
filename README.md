# DNS Security Evaluation Test Suite
> Palo Alto Networks Advanced DNS Security – Proof of Value

Scripts Python + servidor DNS rogue en Azure para validar las 5 categorías de amenaza clave de **Advanced DNS Security**.

---

## Cómo funciona

```
Cliente (scripts Python)
      │  DNS queries
      ▼
PAN-OS Firewall  ◄─── Advanced DNS Security activo
      │
      ▼
Servidor DNS Rogue (Azure VM – CoreDNS)
  • Spoofea dominios configurados en spoofing.conf
  • *.exfil.lab  → IP aleatoria  (exfiltración)
  • *.c2.lab     → IP aleatoria  (C2 beaconing)
  • Resto        → forward a 8.8.8.8
```

---

## PASO 0 – Preparación (hacer una sola vez)

### 0.1 – Obtener el código y las dependencias (máquina cliente)

**Opción A – Clonar desde GitHub** *(recomendado)*

```bash
git clone https://github.com/<TU_USUARIO>/dns-sec-tools.git
cd dns-sec-tools
pip install -r requirements.txt
```

**Opción B – Copiar desde otro equipo vía SCP**

```bash
scp -r /ruta/local/dns-sec-tools/ usuario@cliente:/ruta/destino/
cd /ruta/destino/dns-sec-tools
pip install -r requirements.txt
```

### 0.2 – Desplegar el servidor DNS rogue en Azure

> Necesitas la Azure CLI instalada y con sesión iniciada (`az login`).

```bash
# 1. Crear VM (anota la publicIpAddress del output → ROGUE_DNS_IP)
az group create --name dns-sec-lab --location westeurope

az vm create \
  --resource-group dns-sec-lab \
  --name rogue-dns \
  --image Ubuntu2204 \
  --size Standard_B1s \
  --admin-username azureuser \
  --generate-ssh-keys \
  --public-ip-sku Standard

# 2. Abrir el puerto 53 (UDP + TCP)
az network nsg rule create \
  --resource-group dns-sec-lab \
  --nsg-name rogue-dnsNSG \
  --name AllowDNS \
  --protocol "*" \
  --priority 100 \
  --destination-port-range 53 \
  --access Allow

# 3. Conectarse a la VM e instalar CoreDNS
ssh azureuser@<ROGUE_DNS_IP>

COREDNS_VER=$(curl -s https://api.github.com/repos/coredns/coredns/releases/latest | grep tag_name | cut -d'"' -f4)
wget https://github.com/coredns/coredns/releases/download/${COREDNS_VER}/coredns_${COREDNS_VER#v}_linux_amd64.tgz
tar xzf coredns_*.tgz && sudo mv coredns /usr/local/bin/

# Salir de la VM
exit

# 4a. Subir la config a la VM  →  OPCIÓN A: desde GitHub (recomendado)
ssh azureuser@<ROGUE_DNS_IP>
git clone https://github.com/<TU_USUARIO>/dns-sec-tools.git
COREDNS_CONFIG=$HOME/dns-sec-tools/coredns

# 4b. Subir la config a la VM  →  OPCIÓN B: SCP desde tu equipo local
# (ejecuta esto desde tu máquina, no desde la VM)
# scp -r coredns/ azureuser@<ROGUE_DNS_IP>:/tmp/coredns_config
# ssh azureuser@<ROGUE_DNS_IP>
# COREDNS_CONFIG=/tmp/coredns_config

# 5. Instalar la config y arrancar el servicio (en la VM)
sudo mkdir -p /etc/coredns
sudo cp $COREDNS_CONFIG/* /etc/coredns/
sudo cp /etc/coredns/coredns.service /etc/systemd/system/
sudo chmod +x /etc/coredns/setup_coredns.sh
sudo bash /etc/coredns/setup_coredns.sh
sudo systemctl daemon-reload && sudo systemctl enable --now coredns

# 6. Verificar que funciona
dig @127.0.0.1 google.com        # → 203.0.113.1  (spoofed ✓)
dig @127.0.0.1 chunk1.exfil.lab  # → IP aleatoria ✓
dig @127.0.0.1 beacon1.c2.lab    # → IP aleatoria ✓
dig @127.0.0.1 github.com        # → IP real (forward 8.8.8.8) ✓
exit
```

### 0.3 – Editar `config.py`

```python
DNS_RESOLVER       = "10.0.0.1"          # IP del firewall PAN-OS
ROGUE_DNS_IP       = "<ROGUE_DNS_IP>"    # IP de la VM Azure del paso anterior
DRY_RUN            = False               # True = solo imprime, no envía nada
CUSTOM_DOMAINS_URL = ""                  # URL opcional con IOCs (UC1)
```

---

## UC1 – Bloqueo de dominios maliciosos

**Qué hace:** descarga dominios maliciosos frescos de Abuse.ch URLhaus y OpenPhish (y de tu URL personalizada si la defines) y los resuelve a través del firewall.

**Prerequisitos:** firewall encendido con DNS Security activo · `DNS_RESOLVER` configurado

```bash
# Ejecución básica (usa los feeds por defecto)
python uc1_malicious_domains.py

# Con más dominios
python uc1_malicious_domains.py --max 50

# Con tu propia lista de IOCs (URL con un dominio por línea)
python uc1_malicious_domains.py --custom-url http://mi-servidor/iocs.txt

# Modo dry-run (solo muestra qué enviaría, sin enviar)
python uc1_malicious_domains.py --dry-run
```

**Resultado esperado en el firewall:** acción `block` / `sinkhole` en **Monitor → Logs → Threat** con categoría `malware` o `phishing`.

---

## UC2 – Secuestro DNS (DNS Hijacking)

**Qué hace:** resuelve dominios legítimos apuntando al servidor rogue. El servidor devuelve IPs falsas (spoofed). El firewall debe detectar la respuesta anómala.

**Prerequisitos:** servidor Azure desplegado (paso 0.2) · `ROGUE_DNS_IP` configurado

**Personalizar dominios a espofear:**
1. Edita `coredns/spoofing.conf` en la VM Azure:  `dominio  IP_falsa`
2. Ejecuta en la VM: `sudo bash /etc/coredns/setup_coredns.sh`
3. Añade el dominio también a `test_domains.txt` en el cliente

```bash
# Ejecución básica
python uc2_dns_hijacking.py

# Especificando la IP del servidor rogue
python uc2_dns_hijacking.py --rogue-ip <ROGUE_DNS_IP>

# Modo dry-run
python uc2_dns_hijacking.py --dry-run
```

**Resultado esperado:** acción `block` con categoría `dns-hijacking`.

---

## UC3 – Exfiltración de datos vía DNS

**Qué hace:** codifica un texto en Base64, lo divide en trozos de 10–20 caracteres y envía una query DNS por cada trozo como subdominio de `exfil.lab`. El servidor rogue responde con IPs aleatorias.

**Prerequisitos:** servidor Azure desplegado · `ROGUE_DNS_IP` y `DNS_RESOLVER` configurados

```bash
# Exfiltrar un texto directo
python uc3_dns_exfiltration.py --data "Información confidencial Q1 2026"

# Exfiltrar el contenido de un fichero
python uc3_dns_exfiltration.py --file secreto.txt

# Sin especificar nada: el script te pedirá el texto
python uc3_dns_exfiltration.py

# Modo dry-run (muestra las queries sin enviarlas)
python uc3_dns_exfiltration.py --data "test" --dry-run
```

**Resultado esperado:** acción `block` con categoría `dns-tunneling`.

---

## UC4 – Detección de dominios DGA

**Qué hace:** genera dominios pseudo-aleatorios usando los algoritmos DGA reales de 4 familias de malware conocidas y los resuelve a través del firewall.

**Prerequisitos:** firewall encendido con DNS Security activo · `DNS_RESOLVER` configurado  
*(No requiere el servidor Azure)*

```bash
# Ejecutar todas las familias (conficker, cryptolocker, mirai, locky)
python uc4_dga_domains.py

# Seleccionar familias y número de dominios
python uc4_dga_domains.py --families conficker,locky --count 30

# Modo dry-run (muestra los dominios generados sin resolver)
python uc4_dga_domains.py --dry-run
```

| Familia | Algoritmo |
|---|---|
| `conficker` | MD5 con semilla de fecha |
| `cryptolocker` | MD5 diccionario, semilla de fecha |
| `mirai` | Generador congruencial lineal (PRNG) |
| `locky` | Cadena de hashes MD5 |

**Resultado esperado:** acción `block` con categoría `dga`.

---

## UC5 – Beaconing C2 vía DNS

**Qué hace:** simula los patrones de comunicación C2 por DNS de malware real. Las queries van a `*.c2.lab`; el servidor rogue responde con IPs aleatorias.

**Prerequisitos:** servidor Azure desplegado · `ROGUE_DNS_IP` y `DNS_RESOLVER` configurados

```bash
# Ejecutar todos los patrones (cobaltstrike, dnscat2, iodine)
python uc5_c2_dns.py

# Solo Cobalt Strike, 15 ciclos de beacon
python uc5_c2_dns.py --pattern cobaltstrike --beacons 15

# Solo DNScat2
python uc5_c2_dns.py --pattern dnscat2 --beacons 10

# Modo dry-run
python uc5_c2_dns.py --pattern all --dry-run
```

| Patrón | Tipos de registro | Familia simulada |
|---|---|---|
| `cobaltstrike` | A, TXT | Cobalt Strike DNS Beacon |
| `dnscat2` | TXT, CNAME | DNScat2 |
| `iodine` | TXT, A, CNAME | Iodine DNS tunnel |

**Resultado esperado:** acción `block` con categoría `dns-c2`.

---

## Verificar resultados en PAN-OS

**Monitor → Logs → Threat** → filtrar por `category-of-threat eq dns-security`

| UC | Categoría en el log | Acción esperada |
|---|---|---|
| UC1 | `malware` / `phishing` | block / sinkhole |
| UC2 | `dns-hijacking` | block |
| UC3 | `dns-tunneling` | block |
| UC4 | `dga` | block |
| UC5 | `dns-c2` | block |

Los resultados de cada script se guardan también en `results/uc<N>_results_<timestamp>.json`.

---

> ⚠️ **Disclaimer:** Herramientas para evaluaciones de seguridad autorizadas en entornos de laboratorio controlados. No usar en producción sin autorización escrita.
