from django.db.models.signals import post_delete
from django.dispatch import receiver
from django.contrib.contenttypes.models import ContentType
from netbox.plugins.utils import get_plugin_config


from . import models

@receiver(post_delete)
def handle_vulnerable_asset_delete(sender,instance, **kwargs):

    supported_model_class = False
    supported_assets = get_plugin_config("nb_risk", "supported_assets")
    additional_assets = get_plugin_config("nb_risk", "additional_assets")
    supported_assets = supported_assets + additional_assets

    for asset in supported_assets:
        app_label, model = asset.split(".")
        model = ContentType.objects.get(app_label=app_label, model=model).model_class()
        if isinstance(instance, model):
            supported_model_class = True
            break
    
    if supported_model_class:
        related_VulAssings = models.VulnerabilityAssignment.objects.filter(
            asset_object_type=ContentType.objects.get_for_model(instance),
            asset_id=instance.id )
        for vulnAssign in related_VulAssings:
            vulnAssign.delete()
