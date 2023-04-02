from rest_framework import serializers
from django.contrib.contenttypes.models import ContentType
from netbox.api.fields import ChoiceField, ContentTypeField, SerializedPKRelatedField
from netbox.api.serializers import WritableNestedSerializer
from utilities.api import get_serializer_for_model
from drf_yasg.utils import swagger_serializer_method

from netbox.api.serializers import NetBoxModelSerializer
from nb_risk.api.nested_serializers import (
    NestedThreatSourceSerializer,
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


# VulnerabilityAssignment Serializers

class VulnerabilityAssignmentSerializer(NetBoxModelSerializer):
    url = serializers.HyperlinkedIdentityField(view_name="plugins-api:nb_risk-api:vulnerabilityassignment-detail")
    display = serializers.SerializerMethodField('get_display')
    asset_object_type = ContentTypeField(
        queryset=ContentType.objects.filter(choices.AssetTypes),
        required=True,
        allow_null=True
    )
    asset = serializers.SerializerMethodField(read_only=True)
    vulnerability = serializers.SlugRelatedField(slug_field="name", queryset=models.Vulnerability.objects.all())

    asset_object_id = serializers.IntegerField(source='asset.id')

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
            "asset_object_id",
            "asset",
            "vulnerability",
        ]

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