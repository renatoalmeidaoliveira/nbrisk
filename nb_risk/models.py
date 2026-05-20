from django.db import models
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from django.urls import reverse
from django.db.models.functions import Lower
from django.core.exceptions import ValidationError

from netbox.models import NetBoxModel
from dcim.models import Platform, DeviceType
from . import choices

# ThreatSource Model


class ThreatSource(NetBoxModel):

    name = models.CharField("Name", max_length=100, unique=True)
    threat_type = models.CharField(
        "Threat Type",
        max_length=100,
        choices=choices.ThreatTypeChoices,
        default=choices.ThreatTypeChoices.THREAT_TYPE_1,
    )
    capability = models.CharField(
        "Capability",
        max_length=100,
        choices=choices.CapabilityChoices,
        default=choices.CapabilityChoices.CAPABILITY_1,
    )
    intent = models.CharField("Intent", max_length=100, blank=True)
    targeting = models.CharField("Target", max_length=100, blank=True)
    description = models.CharField("Description", max_length=100, blank=True)
    notes = models.TextField("Notes", blank=True)

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:nb_risk:threatsource", args=[self.pk])

    class Meta:
        ordering = ('name',)


# Vulnerability Model


class Vulnerability(NetBoxModel):

    name = models.CharField("Name", max_length=100, unique=True)
    cve = models.CharField("CVE", max_length=100, blank=True)
    description = models.CharField("Description", max_length=100, blank=True)
    notes = models.TextField("Notes", blank=True)

    # CISA KEV fields — populated by sync_kev management command
    in_kev = models.BooleanField(
        "In CISA KEV",
        default=False,
        help_text="This CVE appears in the CISA Known Exploited Vulnerabilities catalog",
    )
    kev_date_added = models.DateField(
        "KEV Date Added",
        null=True,
        blank=True,
        help_text="Date this CVE was added to the CISA KEV catalog",
    )
    kev_ransomware_use = models.CharField(
        "KEV Ransomware Use",
        max_length=50,
        blank=True,
        help_text="Whether this CVE is known to be used in ransomware campaigns",
    )
    kev_required_action = models.TextField(
        "KEV Required Action",
        blank=True,
        help_text="CISA-recommended remediation action",
    )
    kev_due_date = models.DateField(
        "KEV Due Date",
        null=True,
        blank=True,
        help_text="CISA remediation due date for federal agencies",
    )
    kev_vendor_project = models.CharField(
        "KEV Vendor/Project",
        max_length=200,
        blank=True,
    )
    kev_product = models.CharField(
        "KEV Product",
        max_length=200,
        blank=True,
    )

    cvssaccessVector = models.CharField(
        "Access Vector (AV)", max_length=100, blank=True
    )
    cvssaccessComplexity = models.CharField(
        "Access Complexity (AC)", max_length=100, blank=True
    )
    cvssauthentication = models.CharField(
        "Authentication (Au)", max_length=100, blank=True
    )
    cvssconfidentialityImpact = models.CharField(
        "Confidentiality Impact (C)", max_length=100, blank=True
    )
    cvssintegrityImpact = models.CharField(
        "Integrity Impact (I)", max_length=100, blank=True
    )
    cvssavailabilityImpact = models.CharField(
        "Availability Impact (A)", max_length=100, blank=True
    )
    cvssbaseScore = models.FloatField("Base Score", max_length=100, blank=True, null=True,)

    def affected_assets(self):
        return self.vulnerability_assignments.count()

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:nb_risk:vulnerability", args=[self.pk])

    class Meta:
        ordering = ('name',)
        verbose_name = "Vulnerability"
        verbose_name_plural = "Vulnerabilities"
        constraints = (
            models.UniqueConstraint(
                Lower('name'),
                 name="unique_vuln_name"
            ),
        )


# VulnearbilityAssingment Model


class VulnerabilityAssignment(NetBoxModel):

    asset_object_type = models.ForeignKey(
        to=ContentType,
        on_delete=models.CASCADE,
        related_name="+",
        blank=True,
        null=True,
    )
    asset_id = models.PositiveIntegerField(blank=True, null=True)
    asset = GenericForeignKey(
        ct_field="asset_object_type",
        fk_field="asset_id",
    )
    vulnerability = models.ForeignKey(
        to=Vulnerability,
        on_delete=models.PROTECT,
        related_name="vulnerability_assignments",
        verbose_name="Vulnerability",
    )

    @property
    def name(self):
        return f"{self.asset} - {self.vulnerability.name}"

    def __str__(self):
        return f"{self.asset} - {self.vulnerability.name}"
   
    class Meta:
        ordering = ('pk',)
        constraints = (
            models.UniqueConstraint(
                fields=("asset_object_type", "asset_id", "vulnerability"),
                name="%(app_label)s_%(class)s_unique_object_vulnerability",
            ),
        )


# ThreatEvent Model


class ThreatEvent(NetBoxModel):

    name = models.CharField("Name", max_length=100, unique=True)
    threat_source = models.ForeignKey(
        to=ThreatSource,
        on_delete=models.PROTECT,
        related_name="threat_events",
        verbose_name="Threat Source",
        blank=True,
        null=True,
    )
    description = models.CharField("Description", max_length=100, blank=True)
    notes = models.TextField("Notes", blank=True)
    relevance = models.CharField(
        "Relevance",
        max_length=100,
        choices=choices.RelevanceChoices,
        default=choices.RelevanceChoices.RELEVANCE_6,
    )
    likelihood = models.CharField(
        "Likelihood",
        max_length=100,
        choices=choices.LikelihoodChoices,
        default=choices.LikelihoodChoices.LIKELIHOOD_1,
    )
    impact = models.CharField("Impact", max_length=100, unique=True)

    vulnerability = models.ManyToManyField(
        to=VulnerabilityAssignment,
        related_name="threat_events",
        blank=True,
    )

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:nb_risk:threatevent", args=[self.pk])

    class Meta:
        ordering = ('name',)


# Risk Model


class Risk(NetBoxModel):

    name = models.CharField("Name", max_length=100, unique=True)
    notes = models.TextField("Notes", blank=True)
    threat_event = models.ForeignKey(
        to=ThreatEvent,
        on_delete=models.PROTECT,
        related_name="risks",
        verbose_name="Threat Event",
    )
    description = models.CharField("Description", max_length=100, blank=True)
    likelihood = models.CharField(
        "Likelihood",
        max_length=100,
        choices=choices.LikelihoodChoices,
        default=choices.LikelihoodChoices.LIKELIHOOD_1,
    )
    impact = models.CharField(
        "Level of Impact",
        max_length=100,
        choices=choices.ImpactChoices,
        default=choices.ImpactChoices.IMPACT_1,
    )

    @property
    def risk_level(self):
        if self.impact == choices.ImpactChoices.IMPACT_5:
            return choices.RiskLevelChoices.RISK_LEVEL_5
        elif self.impact == choices.ImpactChoices.IMPACT_4:
            if self.likelihood == choices.LikelihoodChoices.LIKELIHOOD_5:
                return choices.RiskLevelChoices.RISK_LEVEL_5
            else:
                return choices.RiskLevelChoices.RISK_LEVEL_4
        elif self.impact == choices.ImpactChoices.IMPACT_3:
            if self.likelihood == choices.LikelihoodChoices.LIKELIHOOD_5:
                return choices.RiskLevelChoices.RISK_LEVEL_5
            elif self.likelihood == choices.LikelihoodChoices.LIKELIHOOD_4:
                return choices.RiskLevelChoices.RISK_LEVEL_4
            else:
                return choices.RiskLevelChoices.RISK_LEVEL_3
        elif self.impact == choices.ImpactChoices.IMPACT_2:
            if self.likelihood == choices.LikelihoodChoices.LIKELIHOOD_5:
                return choices.RiskLevelChoices.RISK_LEVEL_4
            elif self.likelihood == choices.LikelihoodChoices.LIKELIHOOD_4:
                return choices.RiskLevelChoices.RISK_LEVEL_4
            elif self.likelihood == choices.LikelihoodChoices.LIKELIHOOD_3:
                return choices.RiskLevelChoices.RISK_LEVEL_3
            else:
                return choices.RiskLevelChoices.RISK_LEVEL_2
        elif self.impact == choices.ImpactChoices.IMPACT_1:
            if self.likelihood == choices.LikelihoodChoices.LIKELIHOOD_5:
                return choices.RiskLevelChoices.RISK_LEVEL_4
            elif self.likelihood == choices.LikelihoodChoices.LIKELIHOOD_4:
                return choices.RiskLevelChoices.RISK_LEVEL_3
            elif self.likelihood == choices.LikelihoodChoices.LIKELIHOOD_3:
                return choices.RiskLevelChoices.RISK_LEVEL_2
            elif self.likelihood == choices.LikelihoodChoices.LIKELIHOOD_2:
                return choices.RiskLevelChoices.RISK_LEVEL_1
            else:
                return choices.RiskLevelChoices.RISK_LEVEL_1

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:nb_risk:risk", args=[self.pk])

    class Meta:
        ordering = ('name',)


# Control Model

class Control(NetBoxModel):

    name = name = models.CharField("Name", max_length=100, unique=True)
    description = models.CharField("Description", max_length=100, blank=True)
    notes = models.TextField("Notes", blank=True)
    category = models.CharField(
        "Category",
        max_length=100,
        choices=choices.ControlCategoryChoices,
        default=choices.ControlCategoryChoices.CATEGORY_1,
    )
    risk = models.ManyToManyField(
        Risk,
        verbose_name="Risks",
        blank=True,
    )

    def __str__(self):
        return self.name

    def get_absolute_url(self):
        return reverse("plugins:nb_risk:control", args=[self.pk])

    class Meta:
        ordering = ('name',)


# CPEMapping Model

CPE_PART_CHOICES = (
    ('o', 'Operating System (o)'),
    ('a', 'Application (a)'),
    ('h', 'Hardware (h)'),
)


class CPEMapping(NetBoxModel):
    """
    Maps a NetBox Platform or DeviceType to a verified NVD CPE 2.3 string.
    Used by the Device CVE tab to build precise CPE queries instead of
    guessing vendor/product names from free-text fields.

    Either platform or device_type must be set (not both, not neither).
    The full CPE is assembled as:
        cpe:2.3:{part}:{vendor}:{product}:*:*:*:*:*:{target_sw}:*:*
    with the device's software_version substituted for the version component.
    """
    platform = models.ForeignKey(
        to='dcim.Platform',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='cpe_mappings',
        help_text='Map this CPE to a specific platform (e.g. NX-OS, IOS-XE)',
    )
    device_type = models.ForeignKey(
        to='dcim.DeviceType',
        on_delete=models.CASCADE,
        null=True,
        blank=True,
        related_name='cpe_mappings',
        help_text='Map this CPE to a specific device type (takes precedence over platform)',
    )
    cpe_part = models.CharField(
        'CPE Part',
        max_length=1,
        choices=CPE_PART_CHOICES,
        default='o',
        help_text='CPE part type: o=OS, a=Application, h=Hardware',
    )
    cpe_vendor = models.CharField(
        'CPE Vendor',
        max_length=100,
        help_text='NVD CPE vendor component (e.g. cisco, juniper, paloaltonetworks)',
    )
    cpe_product = models.CharField(
        'CPE Product',
        max_length=100,
        help_text='NVD CPE product component (e.g. nx-os, junos, pan-os)',
    )
    cpe_target_sw = models.CharField(
        'CPE Target Software',
        max_length=100,
        blank=True,
        help_text='Optional 8th CPE component for scoping (e.g. nexus_9000_series). '
                  'Leave blank if not needed.',
    )
    verified = models.BooleanField(
        'Verified',
        default=False,
        help_text='Mark as verified once confirmed against NVD CPE dictionary',
    )
    notes = models.TextField('Notes', blank=True)

    def __str__(self):
        scope = self.platform or self.device_type
        return f"{scope} → cpe:2.3:{self.cpe_part}:{self.cpe_vendor}:{self.cpe_product}"

    def get_absolute_url(self):
        return reverse('plugins:nb_risk:cpemapping', args=[self.pk])

    def clean(self):
        if not self.platform and not self.device_type:
            raise ValidationError('Either a Platform or a Device Type must be specified.')
        if self.platform and self.device_type:
            raise ValidationError('Specify either a Platform or a Device Type, not both.')

    def build_cpe(self, version='*'):
        """Return a full CPE 2.3 string with the given version."""
        target_sw = self.cpe_target_sw or '*'
        return f"cpe:2.3:{self.cpe_part}:{self.cpe_vendor}:{self.cpe_product}:{version}:*:*:*:*:{target_sw}:*:*"

    class Meta:
        ordering = ('cpe_vendor', 'cpe_product')
        verbose_name = 'CPE Mapping'
        verbose_name_plural = 'CPE Mappings'
