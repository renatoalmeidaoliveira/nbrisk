from extras.plugins import PluginConfig
from .version import __version__


class NbriskConfig(PluginConfig):
    name = "nb_risk"
    base_url = "nb_risk"
    verbose_name = "Risk Management"
    description = "NIST 800-30 Risk Management for Netbox"
    version = __version__
    author = "Renato Almdida Oliveira"
    author_email = "renato.almeida.oliveira@gmail.com"
    required_settings = []
    default_settings = {
        "supported_assets": [
            "dcim.device",
            "virtualization.virtualmachine",
            "tenancy.tenant",
            "dcim.site",
        ],
        "additional_assets": [],
    }


config = NbriskConfig  # noqa
