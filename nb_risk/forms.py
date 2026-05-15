from django import forms
from django.contrib.contenttypes.models import ContentType

from netbox.forms import (
    NetBoxModelForm,
    NetBoxModelFilterSetForm,
    NetBoxModelBulkEditForm,
    NetBoxModelImportForm,
)
from ipam.models import IPAddress
from dcim.models import Device, DeviceType
from utilities.forms.fields import (
    DynamicModelMultipleChoiceField,
    SlugField,
    DynamicModelChoiceField,
    CSVModelMultipleChoiceField,
    CSVModelChoiceField,
    CSVContentTypeField,
)
from utilities.forms.rendering import FieldSet

from . import models, choices

# ThreatSource Forms


class ThreatSourceForm(NetBoxModelForm):
    class Meta:
        model = models.ThreatSource
        fields = [
            "name",
            "threat_type",
            "capability",
            "intent",
            "targeting",
            "description",
            "notes",
        ]


class ThreatSourceFilterForm(NetBoxModelFilterSetForm):
    model = models.ThreatSource

    class Meta:
        fields = ["name", "threat_type", "capability", "intent", "targeting"]


class ThreatSourceImportForm(NetBoxModelImportForm):
    class Meta:
        model = models.ThreatSource
        fields = [
            "name",
            "threat_type",
            "capability",
            "intent",
            "targeting",
            "description",
            "notes",
        ]

class ThreatSourceBulkEditForm(NetBoxModelBulkEditForm):
    model = models.ThreatSource

    comments = forms.Textarea(
        attrs={'class': 'font-monospace'}
    )

    class Meta:
        nullable_fields = ("intent", "targeting", "description", "notes")
# ThreatEvent Forms


class ThreatEventForm(NetBoxModelForm):

    vulnerability = DynamicModelMultipleChoiceField(
        queryset=models.VulnerabilityAssignment.objects.all(),
        required=True,
    )

    class Meta:
        model = models.ThreatEvent
        fields = [
            "name",
            "threat_source",
            "description",
            "notes",
            "relevance",
            "likelihood",
            "impact",
            "vulnerability",
        ]


class ThreatEventFilterForm(NetBoxModelFilterSetForm):
    model = models.ThreatEvent

    class Meta:
        fields = [
            "name",
            "threat_source",
            "relevance",
            "likelihood",
            "impact",
            "vulnerability",
        ]


# Vulnerability Forms


class VulnerabilityForm(NetBoxModelForm):

    fieldsets = (
        FieldSet("name", "cve", "description", "notes", name="Vulnerability"),
        FieldSet("cvssaccessVector", "cvssaccessComplexity", "cvssauthentication", "cvssconfidentialityImpact", "cvssintegrityImpact", "cvssavailabilityImpact", "cvssbaseScore", name="CVSSv2 Score"),
      )
      
    class Meta:
        model = models.Vulnerability
        fields = [
            "name",
            "cve",
            "description",
            "notes",
            "cvssaccessVector",
            "cvssaccessComplexity",
            "cvssauthentication",
            "cvssconfidentialityImpact",
            "cvssintegrityImpact",
            "cvssavailabilityImpact",
            "cvssbaseScore",
        ]


class VulnerabilityFilterForm(NetBoxModelFilterSetForm):
    model = models.Vulnerability

    class Meta:
        fields = ["name", "cve"]


class VulnerabilitySearchFilterForm(NetBoxModelFilterSetForm):
    
    model = models.Vulnerability

    fieldsets = (
        FieldSet("cve", "keyword", name="CVE"),
        FieldSet("cpe", "device_type", "version", "part", name="CPE"),
    )    

    cpe = forms.CharField(label="CPE Name", required=False)

    cve = forms.CharField(label="CVE", required=False)

    keyword = forms.CharField(label="Keyword", required=False)

    device_type = DynamicModelChoiceField(
        queryset=DeviceType.objects.all(),
        required=False,
    )
    version = forms.CharField(required=False)

    part = forms.ChoiceField(
        choices=choices.CVE_PART_CHOICES,
        required=False,
    )

class VulnerabilityImportForm(NetBoxModelImportForm):
    class Meta:
        model = models.Vulnerability
        fields = [
            "name",
            "cve",
            "description",
            "notes",
            "cvssaccessVector",
            "cvssaccessComplexity",
            "cvssauthentication",
            "cvssconfidentialityImpact",
            "cvssintegrityImpact",
            "cvssavailabilityImpact",
            "cvssbaseScore",
        ]

# VulnerabilityAssignment Forms


class VulnerabilityAssignmentForm(forms.ModelForm):

    vulnerability = DynamicModelChoiceField(
        queryset=models.Vulnerability.objects.all(),
        required=True,
    )
    

    class Meta:
        model = models.VulnerabilityAssignment
        fields = ["asset_object_type", "asset_id", "vulnerability"]
        widgets = {
            "asset_object_type": forms.HiddenInput(),
            "asset_id": forms.HiddenInput(),
        }


class VulnerabilityAssignmentFilterForm(NetBoxModelFilterSetForm):
    model = models.VulnerabilityAssignment
    vulnerability = DynamicModelChoiceField(
        queryset=models.Vulnerability.objects.all(),
        required=False,
    )

    

class VulnerabilityAssignmentImportForm(NetBoxModelImportForm):
    vulnerability = CSVModelChoiceField(
        label="Vulnerability",
        queryset=models.Vulnerability.objects.all(),
        required=True,
        to_field_name="name",
        error_messages={
            "invalid_choice": "Vulnerability name not found",
        }
    )

    asset_object_type = CSVContentTypeField(
        queryset=ContentType.objects.all(),
        help_text= "Assigned object types",
        required=False,
    )

    ip_address = CSVModelChoiceField(
        label="IP Address",
        queryset= IPAddress.objects.all(),
        required=False,
        to_field_name='address',
        error_messages={
            "invalid_choice": "IPAddress not found",
        }
    )

    def clean(self):
        cleaned_data = super().clean()
        asset_type = self.cleaned_data.get("asset_object_type")
        asset_id = self.cleaned_data.get("asset_id")
        ip_address = self.cleaned_data.get("ip_address")
        vuln = self.cleaned_data.get("vulnerability")
        if asset_type and asset_id and ip_address:
            raise forms.ValidationError(
                "Asset Data and IP Address cannot be assigned at the same time"
            )
        if ip_address is not None:
            if not ip_address.assigned_object:
                raise forms.ValidationError(
                    f"IP Address ({ip_address}) is not assigned to any object"
                )
            else:
                parent = ip_address.assigned_object.parent_object
                if parent is not None:
                    asset_type = ContentType.objects.get_for_model(parent)
                    asset_id = parent.id
                    if models.VulnerabilityAssignment.objects.filter(asset_object_type=asset_type, asset_id=asset_id, vulnerability=vuln).exists():
                        raise forms.ValidationError(
                            f"Vulnerability {vuln} is already assigned to {ip_address} asset object {parent}"
                        )



        return cleaned_data
    

    class Meta:
        model = models.VulnerabilityAssignment
        fields = [
            "asset_object_type",
            "asset_id",
            "vulnerability",
            "ip_address",
        ]


# Risk Forms


class RiskForm(NetBoxModelForm):
    class Meta:
        model = models.Risk
        fields = [
            "name",
            "threat_event",
            "description",
            "notes",
            "likelihood",
            "impact",
        ]


class RiskFilterForm(NetBoxModelFilterSetForm):
    model = models.Risk

    class Meta:
        fields = ["name", "threat_event", "description", "impact", "likelihood"]

# Control Forms

class ControlForm(NetBoxModelForm):
    class Meta:
        model = models.Control
        fields = [
            "name",
            "description",
            "notes",
            "category",
            "risk",
        ]

class ControlFilterForm(NetBoxModelFilterSetForm):
    model = models.Control

    class Meta:
        fields = [
            "name",
            "description",
            "notes",
            "category",
            "risk",
        ]