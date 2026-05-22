# greynoise-lookup

CLI tool for IP, subnet, and ASN threat research. Takes a list of targets, performs reverse DNS lookups and [GreyNoise](https://www.greynoise.io/) community API queries, and writes structured results to CSV or JSON.

## Features

- **Three input types**: individual IPs, CIDR subnets, and ASN numbers
- **Reverse DNS**: PTR record lookup for every IP
- **GreyNoise integration**: noise/RIOT classification via the community API
- **ASN expansion**: resolves ASN to netblocks via Shadowserver, then scans each IP
- **Safety bounds**: configurable max-IPs limit prevents runaway scans on large ASNs
- **Retry with backoff**: handles API rate limits and transient failures
- **Dry-run mode**: validate input without making API calls
- **CSV or JSON output**: choose your format with `--format`

## Installation

```bash
git clone https://github.com/yourusername/greynoise-lookup.git
cd greynoise-lookup
python3 -m venv .venv
source .venv/bin/activate
pip install -e .
```

## Usage

Create an input file with one target per line:

```text
8.8.8.8
1.1.1.1
192.168.1.0/24
AS7029
```

Run the tool:

```bash
# Basic usage (reads iplist.txt, writes results.csv)
greynoise-lookup

# Custom input/output
greynoise-lookup -i targets.txt -o scan_results.csv

# JSON output
greynoise-lookup --format json -i targets.txt

# Dry run — classify input without querying APIs
greynoise-lookup --dry-run -i targets.txt

# Verbose logging
greynoise-lookup -v -i targets.txt

# Limit subnet/ASN expansion to 100 IPs
greynoise-lookup --max-ips 100 -i targets.txt
```

### CLI Options

| Flag | Default | Description |
|------|---------|-------------|
| `-i`, `--input` | `iplist.txt` | Input file path |
| `-o`, `--output` | `results.csv` / `results.json` | Output file path (auto-selects extension from format) |
| `--format` | `csv` | Output format: `csv` or `json` |
| `--max-ips` | `10000` | Max IPs per subnet/ASN expansion |
| `-v`, `--verbose` | off | Debug-level logging |
| `--dry-run` | off | Parse input only, no API calls |

## API Key (Optional)

The GreyNoise community API works without authentication but is rate-limited. For higher limits, get a free key at [greynoise.io/plans](https://www.greynoise.io/plans) and add it to a `.env` file:

```bash
cp .env.example .env
# Edit .env and add your key
```

## Sample Output

```csv
entry,ip,ptr,noise,riot,classification,name,link,last_seen,message
8.8.8.8,8.8.8.8,dns.google.,False,True,benign,Google Public DNS,https://viz.greynoise.io/riot/8.8.8.8,2024-01-15,Success
1.1.1.1,1.1.1.1,one.one.one.one.,False,True,benign,Cloudflare DNS,https://viz.greynoise.io/riot/1.1.1.1,2024-01-15,Success
```

After the scan, a summary is printed:

```
INFO: --- Summary ---
INFO: Total IPs scanned: 2
INFO: Noise (observed scanning): 0
INFO: RIOT (known benign service): 2
INFO: Classifications:
INFO:   benign: 2
```

## Architecture

```
iplist.txt ─> parser ─> lookup ─> writer ─> results.csv / results.json
               │          │
               │          ├── reverse_dns()     (dnspython)
               │          └── query_greynoise()  (requests)
               │
               ├── classify_entry()   IP / Subnet / ASN / Invalid
               ├── expand_subnet()    CIDR -> IP list
               └── resolve_asn()      Shadowserver API -> CIDR list
```

| Module | Responsibility |
|--------|---------------|
| `models.py` | Frozen dataclasses (`ClassifiedEntry`, `LookupResult`) and `EntryType` enum |
| `parser.py` | Input classification, subnet expansion, ASN resolution |
| `lookup.py` | Reverse DNS and GreyNoise API queries with retry logic |
| `writer.py` | CSV/JSON output and summary statistics |
| `cli.py` | Argument parsing, logging setup, orchestration |

## License

MIT
