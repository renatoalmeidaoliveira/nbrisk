from django.db import models
from django.contrib.contenttypes.models import ContentType
from django.contrib.contenttypes.fields import GenericForeignKey
from django.urls import reverse

from netbox.models import NetBoxModel
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
        return reverse(
            "plugins:nb_risk:threatsource", args=[self.pk]
        )


# Vulnerability Model


class Vulnerability(NetBoxModel):

    name = models.CharField("Name", max_length=100, unique=True)
    cve = models.CharField("CVE", max_length=100, blank=True)
    description = models.CharField("Description", max_length=100, blank=True)
    notes = models.TextField("Notes", blank=True)

    def __str__(self):
        return self.name
    
    def get_absolute_url(self):
        return reverse(
            "plugins:nb_risk:vulnerability", args=[self.pk]
        )

    class Meta:
        verbose_name_plural = "Vulnerabilities"

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
        constraints = (
            models.UniqueConstraint(
                fields=('asset_object_type', 'asset_id', 'vulnerability'),
                name='%(app_label)s_%(class)s_unique_object_vulnerability'
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
        return reverse(
            "plugins:nb_risk:threatevent", args=[self.pk]
        )

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
        return reverse(
            "plugins:nb_risk:risk", args=[self.pk]
        )