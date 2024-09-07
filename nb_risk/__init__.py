from netbox.plugins import PluginConfig
from .version import __version__



class NbriskConfig(PluginConfig):
    name = "nb_risk"
    base_url = "nb_risk"
    verbose_name = "Risk Management"
    description = "NIST 800-30 Risk Management for Netbox"
    version = __version__
    author = "Renato Almeida de Oliveira Zaroubin"
    author_email = "renato.almeida.oliveira@gmail.com"
    min_version = "4.1.0"
    max_version = "4.1.99"
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
    }
    
    def ready(self):
        from . import signals
        super().ready()

config = NbriskConfig  # noqa
