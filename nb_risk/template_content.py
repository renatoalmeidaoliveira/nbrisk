from extras.plugins import PluginTemplateExtension
from django.conf import settings
from packaging import version

NETBOX_CURRENT_VERSION = version.parse(settings.VERSION)

def create_button(model_name):
    
    class Button(PluginTemplateExtension):
        model = model_name
        def buttons(self):
            return self.render('nb_risk/vulnerability_assignment_button.html')
    
    return Button

supported_assets = [ "dcim.device", "virtualization.virtualmachine", "dcim.site", "tenancy.tenant" ]
template_extensions = []
for supported_asset in supported_assets:
    template_extensions.append(create_button(supported_asset))


