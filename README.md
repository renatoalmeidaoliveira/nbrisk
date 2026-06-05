## Netbox NBRisk
[NetBox](https://github.com/netbox-community/netbox) plugin inspired by NIST 800-30 Risk Management.

> **Note:** The original upstream repository is no longer actively maintained. This fork adds compatibility with NetBox 4.5.x and requires Python 3.12+.

## Compatibility

See the [compatibility matrix](COMPATIBILITY.md) for supported NetBox versions.

## Installation

Add to `local_requirements.txt` to ensure automatic re-installation during NetBox upgrades:

```shell
echo "git+https://github.com/droolingtaz/nbrisk.git@main#egg=NbRisk" >> /opt/netbox/local_requirements.txt
```

Install, migrate, and run the initial data syncs:

```shell
source /opt/netbox/venv/bin/activate
pip install "git+https://github.com/droolingtaz/nbrisk.git@main#egg=NbRisk"
cd /opt/netbox/netbox
python3 manage.py migrate nb_risk
python3 manage.py sync_kev       # sync CISA Known Exploited Vulnerabilities catalog
python3 manage.py sync_epss      # sync EPSS exploit prediction scores
sudo systemctl restart netbox netbox-rq
```

## Enabling the Plugin

Add to `configuration.py`:

```python
PLUGINS = ["nb_risk"]
```

## Configuration

All configuration goes in `PLUGINS_CONFIG` in `configuration.py`:

```python
PLUGINS_CONFIG = {
    'nb_risk': {
        # NVD API key — strongly recommended to avoid rate limiting
        # 5 req/30s without a key, 50 req/30s with one
        # Get a free key at https://nvd.nist.gov/developers/request-an-api-key
        'nvd_api_key': 'your-api-key-here',

        # Additional models to support vulnerability assignment beyond the defaults
        # Defaults: dcim.device, virtualization.virtualmachine, tenancy.tenant, dcim.site
        'additional_assets': [
            'dcim.platform',
        ],
    },
}
```

### NVD API Key

The CVE search feature queries the [NIST NVD API](https://nvd.nist.gov/developers/vulnerabilities). Without an API key requests are rate-limited to 5 per 30 seconds; with a key the limit is 50 per 30 seconds. Get a free key at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).

### Proxy Settings

The plugin uses NetBox's built-in `HTTP_PROXIES` setting from `configuration.py` for all external API requests (NVD, CISA KEV, EPSS) — no separate proxy config needed:

```python
HTTP_PROXIES = {
    'http': 'http://proxy.example.com:8080',
    'https': 'http://proxy.example.com:8080',
}
```

---

## Device CVE Tab

A **CVEs** tab appears on every Device detail page. It queries NVD for CVEs matching the device's running software and cross-references results against the CISA KEV catalog and EPSS scores.

### Requirements

- The `software_version` custom field must be set on the device (created automatically on first install, or manually via `manage.py shell`)
- A **CPE Mapping** must exist for the device's platform or device type (see below)

### CVE result columns

| Column | Source | Description |
|---|---|---|
| CVE ID | NVD | Links to nvd.nist.gov |
| KEV | CISA | Red badge if actively exploited in the wild |
| EPSS | FIRST.org | Probability of exploitation in next 30 days |
| CVSS | NVD | Version and base score with colour coding |
| Attack Vector | NVD | Network, Adjacent, Local, Physical |
| Import | — | One-click import into Vulnerabilities |

### CVSS score colours

| Score | Severity |
|---|---|
| 9.0+ | 🔴 Critical |
| 7.0–8.9 | 🟡 High |
| 4.0–6.9 | 🔵 Medium |
| Below 4.0 | ⚪ Low |

### EPSS score colours

| Score | Meaning |
|---|---|
| ≥ 0.5 | 🔴 High exploitation probability |
| ≥ 0.1 | 🟡 Moderate exploitation probability |
| ≥ 0.01 | 🔵 Low exploitation probability |
| < 0.01 | ⚪ Very low exploitation probability |

---

## CPE Mappings

CPE Mappings are the key to accurate, vendor-agnostic CVE matching. They map a NetBox **Platform** or **Device Type** to a verified NVD CPE 2.3 string. Without a mapping, CVE lookups cannot be performed reliably.

### CPE Lookup Assistant

Go to **Risk Assessment → CVE Integration → CPE Mappings → Lookup** to search the NVD CPE dictionary by keyword and create mappings with one click.

### Common platform mappings

| Platform | CPE Vendor | CPE Product | Part | Target SW |
|---|---|---|---|---|
| NX-OS | cisco | nx-os | o | nexus_9000_series |
| IOS-XE | cisco | ios_xe | o | |
| IOS | cisco | ios | o | |
| Junos | juniper | junos | o | |
| EOS | arista | eos | o | |
| PAN-OS | paloaltonetworks | pan-os | o | |
| FortiOS | fortinet | fortios | o | |
| Ubuntu 22.04 | canonical | ubuntu_linux | o | |
| Windows Server 2022 | microsoft | windows_server_2022 | o | |

The **Target SW** field (8th CPE component) scopes results to a specific platform family. For example `nexus_9000_series` returns only CVEs specifically affecting Nexus 9000 switches rather than all NX-OS CVEs.

---

## CISA KEV Integration

The [CISA Known Exploited Vulnerabilities](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) catalog lists CVEs actively exploited in the wild. The plugin cross-references this automatically.

### Sync command

```shell
python3 manage.py sync_kev           # sync all Vulnerability records
python3 manage.py sync_kev --dry-run # preview without changes
```

Run this daily — the KEV catalog is updated by CISA as new exploits are confirmed.

---

## EPSS Integration

[FIRST.org EPSS](https://www.first.org/epss/) (Exploit Prediction Scoring System) provides a daily-updated probability score (0.0–1.0) that a CVE will be exploited in the next 30 days. No API key required.

### Sync command

```shell
python3 manage.py sync_epss           # sync all Vulnerability records
python3 manage.py sync_epss --dry-run # preview scores without changes
```

EPSS scores are also fetched in real-time for CVE Search results and the Device CVE tab, with 24-hour per-CVE Redis caching.

### Prioritization framework

Combining all three signals:

| Signal | Meaning |
|---|---|
| **KEV** | Already being exploited — remediate immediately |
| **High EPSS (≥ 0.5)** | High probability of exploitation soon |
| **High CVSS (≥ 9.0)** | Critical severity |
| All three | Highest priority — act now |

---

## Management Commands

| Command | Description |
|---|---|
| `manage.py sync_kev` | Sync CISA KEV catalog against Vulnerability records |
| `manage.py sync_kev --dry-run` | Preview KEV matches without changes |
| `manage.py sync_epss` | Sync EPSS scores for all Vulnerability records |
| `manage.py sync_epss --dry-run` | Preview EPSS scores without changes |

---

## Development

A Docker Compose development environment is included. It spins up NetBox 4.5.9 with the plugin installed in editable mode alongside PostgreSQL 15 and Redis 7.

```shell
make cbuild     # build containers
make debug      # start in foreground
make start      # start in background
make stop       # stop
make destroy    # destroy including database
make nbshell    # open NetBox shell
make adduser    # create superuser
make migrations # generate migrations after model changes
make test       # run tests
```

---

## Screenshots

### Plugin Menu

![image](https://user-images.githubusercontent.com/16046203/214701799-d587bc22-092d-494f-9beb-18b95306be9d.png)

### Vulnerability View

![image](https://user-images.githubusercontent.com/16046203/214468549-afc2de89-2d1e-412e-96d5-839ac47d4d9e.png)

### Affected Assets

![image](https://user-images.githubusercontent.com/16046203/214468616-4d45b1ff-9887-43b9-9c17-0047ff5a5f02.png)

### Device Vulnerabilities

![image](https://user-images.githubusercontent.com/16046203/214468700-81d21799-8381-4fca-a9bf-204a41211736.png)

### Threat Event View

![image](https://user-images.githubusercontent.com/16046203/214702045-c3e01bfe-1b2c-4100-ae00-c42d3f23cfdb.png)

### Risks View

![image](https://user-images.githubusercontent.com/16046203/214702218-b74e9f49-6a0d-4789-8518-32e99ef7fead.png)
