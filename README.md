7# Netbox Nbrisk
[Netbox](https://github.com/netbox-community/netbox) Plugin inspired in NIST 800-30 Risk Management  **BETA VERSION**


## Compatibility

This plugin in compatible with [NetBox](https://netbox.readthedocs.org/) 3.4.0 and later.

## Installation

The plugin is available as a Python package and can be installed with pip.
To ensure NBRisk plugin is automatically re-installed during future upgrades, create a file named local_requirements.txt (if not already existing) in the NetBox root directory (alongside requirements.txt) and list the NBRisk package:

```shell
# echo "NbRisk==0.1.0" >> local_requirements.txt
```

Once installed, the plugin needs to be enabled in your configuration.py

```python
# In your configuration.py
PLUGINS = ["nb_risk"]
```

First run source /opt/netbox/venv/bin/activate to enter the Python virtual environment.

Then run
```
cd /opt/netbox/netbox
pip install NbRisk
python3 manage.py migrate nb_risk
```
Not ready

## Configuration

None

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

