from extras.plugins import PluginTemplateExtension
from extras.plugins.utils import get_plugin_config
from django.conf import settings
from packaging import version

NETBOX_CURRENT_VERSION = version.parse(settings.VERSION)


def create_button(model_name):
    class Button(PluginTemplateExtension):
        model = model_name

        def buttons(self):
            return self.render("nb_risk/vulnerability_assignment_button.html")

    return Button


supported_assets = get_plugin_config("nb_risk", "supported_assets")
additional_assets = get_plugin_config("nb_risk", "additional_assets")
supported_assets = supported_assets + additional_assets

template_extensions = []
for supported_asset in supported_assets:
    template_extensions.append(create_button(supported_asset))
