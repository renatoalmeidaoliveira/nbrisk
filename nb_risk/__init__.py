from netbox.plugins import PluginConfig
from .version import __version__



class NbriskConfig(PluginConfig):
    name = "nb_risk"
    base_url = "nb_risk"
    verbose_name = "Netbox Risk"
    description = "Risk Management for NetBox, inspired by NIST 800-30."
    version = __version__
    author = "Blake Parker"
    author_email = "blake.parker@e280.com"
    min_version = "4.5.0"
    max_version = "4.5.99"
    required_settings = []
    default_settings = {
        "supported_assets": [
            "dcim.device",
            "virtualization.virtualmachine",
            "tenancy.tenant",
            "dcim.site",
        ],
        "additional_assets": [],
        "proxies": {},
        "nvd_api_key": None,
    }
    
    def ready(self):
        from . import signals
        super().ready()

config = NbriskConfig  # noqa
