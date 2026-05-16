from netbox.plugins import PluginTemplateExtension
from netbox.plugins.utils import get_plugin_config
from utilities.views import ViewTab


def create_button(model_name):
    class Button(PluginTemplateExtension):
        # NetBox 4.3+ requires `models` (list) instead of the deprecated singular `model`
        models = [model_name]

        def buttons(self):
            return self.render("nb_risk/vulnerability_assignment_button.html")

    return Button


class DeviceCVETab(PluginTemplateExtension):
    """
    Adds a 'CVEs' tab to the Device detail page.
    Queries NVD for CVEs matching the device's software version
    (via the netbox_software_tracker custom field), manufacturer,
    and platform.
    """
    models = ["dcim.device"]

    def tabs(self):
        return [
            ViewTab(
                label="CVEs",
                badge=None,
                permission="dcim.view_device",
                url_name="plugins:nb_risk:device_cve",
                url_kwargs={"pk": self.context["object"].pk},
            )
        ]


supported_assets = get_plugin_config("nb_risk", "supported_assets")
additional_assets = get_plugin_config("nb_risk", "additional_assets")
supported_assets = supported_assets + additional_assets

template_extensions = [DeviceCVETab]
for supported_asset in supported_assets:
    template_extensions.append(create_button(supported_asset))
