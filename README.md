## Netbox NBRisk
[NetBox](https://github.com/netbox-community/netbox) plugin inspired by NIST 800-30 Risk Management.

> **Note:** The original upstream repository is no longer actively maintained. This fork adds compatibility with NetBox 4.5.x and requires Python 3.12+.

## Compatibility

| NBRisk Version | NetBox Version | Python |
|---|---|---|
| 45.0.0 (this fork) | 4.5.x | 3.12+ |
| 41.0.2 (upstream) | 4.1.x | 3.10+ |
| upstream | 4.0.x | 3.10+ |
| upstream | 3.5.8 – 3.7.x | 3.8+ |
| upstream | 3.5.0 – 3.5.7 | 3.8+ |
| upstream | 3.4.x | 3.8+ |

## Installation

The recommended approach is to install directly from this fork. To ensure the plugin is automatically re-installed during future NetBox upgrades, add it to your `local_requirements.txt`:

```shell
echo "git+https://github.com/droolingtaz/nbrisk.git@main#egg=NbRisk" >> /opt/netbox/local_requirements.txt
```

Then install and migrate:

```shell
source /opt/netbox/venv/bin/activate
pip install "git+https://github.com/droolingtaz/nbrisk.git@main#egg=NbRisk"
cd /opt/netbox/netbox
python3 manage.py migrate nb_risk
sudo systemctl restart netbox netbox-rq
```

## Enabling the Plugin

Add the plugin to your `configuration.py`:

```python
PLUGINS = ["nb_risk"]
```

## Configuration

All configuration goes in the `PLUGINS_CONFIG` section of `configuration.py`:

```python
PLUGINS_CONFIG = {
    'nb_risk': {
        # NVD API key — strongly recommended to avoid rate limiting (5 req/30s without, 50/30s with)
        # Get a free key at https://nvd.nist.gov/developers/request-an-api-key
        'nvd_api_key': 'your-api-key-here',

        # Optional proxy settings for NVD API requests
        'proxies': {
            'http': 'http://proxy.example.com:8080',
            'https': 'http://proxy.example.com:8080',
        },

        # Additional models to support vulnerability assignment beyond the defaults
        # Defaults: dcim.device, virtualization.virtualmachine, tenancy.tenant, dcim.site
        'additional_assets': [
            'dcim.platform',
        ],
    },
}
```

### NVD API Key

The CVE search feature queries the [NIST NVD API](https://nvd.nist.gov/developers/vulnerabilities). Without an API key requests are rate-limited to 5 per 30 seconds; with a key the limit is 50 per 30 seconds. A free key can be requested at [nvd.nist.gov/developers/request-an-api-key](https://nvd.nist.gov/developers/request-an-api-key).

### Additional Assets

To assign vulnerabilities to additional models beyond the defaults (`dcim.device`, `virtualization.virtualmachine`, `tenancy.tenant`, `dcim.site`), add them via `additional_assets` in `PLUGINS_CONFIG`:

```python
PLUGINS_CONFIG = {
    'nb_risk': {
        'additional_assets': [
            'dcim.platform',
        ],
    },
}
```

Multiple models can be listed:

```python
PLUGINS_CONFIG = {
    'nb_risk': {
        'additional_assets': [
            'dcim.platform',
            'dcim.rack',
        ],
    },
}
```

## Development

A Docker Compose development environment is included. It spins up NetBox 4.5.9 with the plugin installed in editable mode alongside PostgreSQL 15 and Redis 7.

```shell
# Build the development containers
make cbuild

# Start in the foreground (with logs)
make debug

# Start in the background
make start

# Stop
make stop

# Destroy (including database volume)
make destroy

# Open a NetBox shell
make nbshell

# Create a superuser
make adduser

# Generate migrations after model changes
make migrations

# Run tests
make test
```

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
