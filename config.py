# =============================================================================
# DNS Security Evaluation Test Suite – Shared Configuration
# =============================================================================
# Edit this file before running any test script.
# =============================================================================

# ---------------------------------------------------------------------------
# Network
# ---------------------------------------------------------------------------

# IP of the DNS resolver to send all test queries through.
# In production: IP of the PAN-OS firewall (or its DNS proxy interface).
# In lab without firewall: use the ROGUE_DNS_IP directly.
DNS_RESOLVER = "8.8.8.8"

# Public IP of the Azure rogue DNS server (set after deploying the server).
ROGUE_DNS_IP = "62.36.225.150"   # TODO: fill in after Azure deployment

# DNS query timeout (seconds)
QUERY_TIMEOUT = 5

# Delay between consecutive DNS queries (seconds) – avoids rate-limiting
QUERY_DELAY_SEC = 0.5

# ---------------------------------------------------------------------------
# Rogue DNS base domains (must route through ROGUE_DNS_IP)
# ---------------------------------------------------------------------------

# Base domain for DNS exfiltration test (UC3).
# The rogue DNS server responds to *.EXFIL_BASE_DOMAIN with random IPs.
EXFIL_BASE_DOMAIN = "exfil.lab"

# Base domain for C2 beaconing test (UC5).
# The rogue DNS server responds to *.C2_BASE_DOMAIN with random IPs.
C2_BASE_DOMAIN = "c2tests.com"

# ---------------------------------------------------------------------------
# Dry-run mode
# ---------------------------------------------------------------------------
# When True: queries are only printed/logged – nothing is actually sent.
# When False: queries are sent to DNS_RESOLVER (or ROGUE_DNS_IP where noted).
DRY_RUN = False

# ---------------------------------------------------------------------------
# UC1 – Malicious domain sources
# ---------------------------------------------------------------------------

# Maximum number of domains to test per feed (keep low to avoid hammering FW)
UC1_MAX_DOMAINS_PER_FEED = 30

# (Optional) URL to a plain-text file with one domain per line.
# Leave empty ("") to skip. Populate with your own fresh malicious IOCs.
CUSTOM_DOMAINS_URL = ""  # e.g. "http://myserver.example.com/iocs.txt"

# ---------------------------------------------------------------------------
# UC3 – DNS Exfiltration
# ---------------------------------------------------------------------------

# Chunk size range (chars). Each Base64 segment is a random length in this range.
EXFIL_CHUNK_MIN = 10
EXFIL_CHUNK_MAX = 20

# Add a numeric index prefix to each chunk label (e.g. 1-<chunk>.exfil.lab)
EXFIL_INDEXED = True

# ---------------------------------------------------------------------------
# UC4 – DGA Domain Generation
# ---------------------------------------------------------------------------

# How many DGA domains to generate per family
DGA_DOMAINS_PER_FAMILY = 20

# Which DGA families to test. Available: conficker, cryptolocker, mirai, locky
DGA_FAMILIES = ["conficker", "cryptolocker", "mirai", "locky"]

# ---------------------------------------------------------------------------
# UC5 – C2 DNS Beaconing
# ---------------------------------------------------------------------------

# C2 patterns to simulate. Available: cobaltstrike, dnscat2, iodine
C2_PATTERNS = ["cobaltstrike", "dnscat2", "iodine"]

# Number of beacon cycles to simulate per pattern
C2_BEACON_COUNT = 10

# Min/max beacon interval in seconds (randomised each cycle)
C2_BEACON_INTERVAL_MIN = 2
C2_BEACON_INTERVAL_MAX = 8

# ---------------------------------------------------------------------------
# Output
# ---------------------------------------------------------------------------
RESULTS_DIR = "results"
