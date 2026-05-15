## Netbox NBRisk
[NetBox](https://github.com/netbox-community/netbox) plugin inspired by NIST 800-30 Risk Management.

> **Note:** The original upstream repository is no longer actively maintained. This fork adds compatibility with NetBox 4.5.x and requires Python 3.12+.

## Compatibility

| NBRisk Branch | NetBox Version | Python |
|---|---|---|
| `NetBox_v4.1` (this fork) | 4.5.x | 3.12+ |
| `NetBox_v4.1` (upstream) | 4.1.x | 3.10+ |
| upstream | 4.0.x | 3.10+ |
| upstream | 3.5.8 – 3.7.x | 3.8+ |
| upstream | 3.5.0 – 3.5.7 | 3.8+ |
| upstream | 3.4.x | 3.8+ |

## Installation

### Installing from this fork (NetBox 4.5.x)

The recommended approach is to install directly from this fork's `NetBox_v4.1` branch. To ensure the plugin is automatically re-installed during future NetBox upgrades, add it to your `local_requirements.txt`:

```shell
echo "git+https://github.com/droolingtaz/nbrisk.git@NetBox_v4.1#egg=NbRisk" >> /opt/netbox/local_requirements.txt
```

Then install and migrate:

```shell
source /opt/netbox/venv/bin/activate
pip install "git+https://github.com/droolingtaz/nbrisk.git@NetBox_v4.1#egg=NbRisk"
cd /opt/netbox/netbox
python3 manage.py migrate nb_risk
```

## Enabling the Plugin

Add the plugin to your `configuration.py`:

```python
PLUGINS = ["nb_risk"]
```

## Configuration

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

Replace `app_label.model_name` with the target model. Multiple models can be listed. For example:

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
