from rest_framework import serializers
from django.contrib.contenttypes.models import ContentType
from netbox.api.fields import ChoiceField, ContentTypeField, SerializedPKRelatedField
from netbox.api.serializers import WritableNestedSerializer
from utilities.api import get_serializer_for_model


from netbox.api.serializers import NetBoxModelSerializer
from nb_risk.api.nested_serializers import (
    NestedRiskSerializer,
)
from .. import models, choices

# ThreatSource Serializers

class ThreatSourceSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:nb_risk-api:threatsource-detail")
    display = serializers.SerializerMethodField('get_display')
    threat_type = ChoiceField(choices=choices.ThreatTypeChoices)
    capability = ChoiceField(choices=choices.CapabilityChoices)

    def get_display(self, obj):
        return obj.name

    class Meta:
        model = models.ThreatSource
        fields = [
            "id",
            "url",
            "display",
            "name",
            "threat_type",
            "capability",
            "intent",
            "targeting",
            "description",
        ]
        brief_fields = ['id', 'url', 'display', 'name', 'description']

# ThreatEvent Serializers

class ThreatEventSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:nb_risk-api:threatevent-detail")
    display = serializers.SerializerMethodField('get_display')
    threat_source = serializers.SlugRelatedField(slug_field="name", queryset=models.ThreatSource.objects.all())
    relevance = ChoiceField(choices=choices.RelevanceChoices)
    likelihood = ChoiceField(choices=choices.LikelihoodChoices)


    def get_display(self, obj):
        return obj.name

    class Meta:
        model = models.ThreatEvent
        fields = [
            "id",
            "url",
            "display",
            "name",
            "threat_source",
            "relevance",
            "likelihood",
            "impact",
            "vulnerability",
        ]

        brief_fields = ['id', 'url', 'display', 'name', 'description']

# Vulnerability Serializers

class VulnerabilitySerializer(NetBoxModelSerializer):
    
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:nb_risk-api:vulnerability-detail")
    display = serializers.SerializerMethodField('get_display')

    def get_display(self, obj):
        return obj.name

    class Meta:
        model = models.Vulnerability
        fields = [
            "id",
            "url",
            "display",
            "name",
            "cve",
            "description",
        ]

        brief_fields = ['id', 'url', 'display', 'name', 'description']


# VulnerabilityAssignment Serializers

class VulnerabilityAssignmentSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:nb_risk-api:vulnerabilityassignment-detail")
    display = serializers.SerializerMethodField('get_display')
    asset_object_type = ContentTypeField(
        queryset=ContentType.objects.filter(choices.AssetTypes),
        required=True,
    )
    asset = serializers.SerializerMethodField('get_asset')
    vulnerability = serializers.SlugRelatedField(slug_field="name", queryset=models.Vulnerability.objects.all())

    asset_id = serializers.IntegerField(source='asset.id', write_only=True)

    def validate(self, data):
        asset_id = data['asset']['id']
        asset_object_type = data['asset_object_type']
        asset = asset_object_type.get_object_for_this_type(id=asset_id)
        data['asset'] = asset
        return super().validate(data)

    def get_asset(self, obj):
        if obj.asset is None:
            return None
        serializer = get_serializer_for_model(obj.asset, prefix='Nested')
        context = {'request': self.context['request']}
        return serializer(obj.asset, context=context).data
    
    def get_display(self, obj):
        return obj.name


    class Meta:
        model = models.VulnerabilityAssignment
        fields = [
            "id",
            "url",
            "display",
            "asset_object_type",
            "asset_id",
            "asset",
            "vulnerability",
        ]
        brief_fields = ['id', 'url', 'display']

# Risk Serializers

class RiskSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:nb_risk-api:risk-detail")
    display = serializers.SerializerMethodField('get_display')
    
    threat_event = serializers.SlugRelatedField(slug_field="name", queryset=models.ThreatEvent.objects.all())

   
    def get_display(self, obj):
        return obj.name

    class Meta:
        model = models.Risk
        fields = [
            "id",
            "url",
            "display",
            "threat_event",
            "description",
            "likelihood",
            "impact",
            "notes",
        ]

# Control Serializers

class ControlSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:nb_risk-api:control-detail")
    display = serializers.SerializerMethodField('get_display')
    risk = NestedRiskSerializer(many=True,required=False, allow_null=True)

    def get_display(self, obj):
        return obj.name
    
    class Meta:
        model = models.Control
        fields = [
            "id",
            "url",
            "display",
            "name",
            "description",
            "notes",
            "risk"
        ]