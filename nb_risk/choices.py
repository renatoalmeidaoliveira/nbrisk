from django.db.models import Q
from utilities.choices import ChoiceSet

# Define a set of choices for the Threat Type
class ThreatTypeChoices(ChoiceSet):

    THREAT_TYPE_1 = "ADVERSARIAL"
    THREAT_TYPE_2 = "ACCIDENTAL"
    THREAT_TYPE_3 = "STRUCTURAL"
    THREAT_TYPE_4 = "ENVIRONMENTAL"

    CHOICES = (
        (THREAT_TYPE_1, "ADVERSARIAL"),
        (THREAT_TYPE_2, "ACCIDENTAL"),
        (THREAT_TYPE_3, "STRUCTURAL"),
        (THREAT_TYPE_4, "ENVIRONMENTAL"),
    )


# Define a set of choices for the Capability
class CapabilityChoices(ChoiceSet):

    CAPABILITY_1 = "Very High"
    CAPABILITY_2 = "High"
    CAPABILITY_3 = "Moderate"
    CAPABILITY_4 = "Low"
    CAPABILITY_5 = "Very Low"

    CHOICES = (
        (CAPABILITY_1, "Very High"),
        (CAPABILITY_2, "High"),
        (CAPABILITY_3, "Moderate"),
        (CAPABILITY_4, "Low"),
        (CAPABILITY_5, "Very Low"),
    )


# Define a set of choices for the Relevance


class RelevanceChoices(ChoiceSet):

    RELEVANCE_1 = "Confirmed"
    RELEVANCE_2 = "Expected"
    RELEVANCE_3 = "Anticipated"
    RELEVANCE_4 = "Predicted"
    RELEVANCE_5 = "Possible"
    RELEVANCE_6 = "N/A"

    CHOICES = (
        (RELEVANCE_1, "Confirmed"),
        (RELEVANCE_2, "Expected"),
        (RELEVANCE_3, "Anticipated"),
        (RELEVANCE_4, "Predicted"),
        (RELEVANCE_5, "Possible"),
        (RELEVANCE_6, "N/A"),
    )


# Define a set of choices for the Likelihood


class LikelihoodChoices(ChoiceSet):

    LIKELIHOOD_1 = "Very High"
    LIKELIHOOD_2 = "High"
    LIKELIHOOD_3 = "Moderate"
    LIKELIHOOD_4 = "Low"
    LIKELIHOOD_5 = "Very Low"

    CHOICES = (
        (LIKELIHOOD_1, "Very High"),
        (LIKELIHOOD_2, "High"),
        (LIKELIHOOD_3, "Moderate"),
        (LIKELIHOOD_4, "Low"),
        (LIKELIHOOD_5, "Very Low"),
    )


# Define a set of choices for the Impact


class ImpactChoices(ChoiceSet):

    IMPACT_1 = "Very High"
    IMPACT_2 = "High"
    IMPACT_3 = "Moderate"
    IMPACT_4 = "Low"
    IMPACT_5 = "Very Low"

    CHOICES = (
        (IMPACT_1, "Very High"),
        (IMPACT_2, "High"),
        (IMPACT_3, "Moderate"),
        (IMPACT_4, "Low"),
        (IMPACT_5, "Very Low"),
    )


# Define Asset Type Choices

AssetTypes = Q(
    Q(app_label="dcim", model="device")
    | Q(app_label="virtualization", model="virtualmachine")
)

# Define Level of Risk Choices


class RiskLevelChoices(ChoiceSet):

    RISK_LEVEL_1 = "Very High"
    RISK_LEVEL_2 = "High"
    RISK_LEVEL_3 = "Moderate"
    RISK_LEVEL_4 = "Low"
    RISK_LEVEL_5 = "Very Low"

    CHOICES = (
        (RISK_LEVEL_1, "Very High"),
        (RISK_LEVEL_2, "High"),
        (RISK_LEVEL_3, "Moderate"),
        (RISK_LEVEL_4, "Low"),
        (RISK_LEVEL_5, "Very Low"),
    )


# Define CVE part choices


class CVE_PART_CHOICES(ChoiceSet):

    PART_1 = "a"
    PART_2 = "o"
    PART_3 = "h"

    CHOICES = (
        (PART_1, "Applications"),
        (PART_2, "Operating Systems"),
        (PART_3, "Hardware Devices"),
    )

# ControlCategoryChoices

class ControlCategoryChoices(ChoiceSet):

    CATEGORY_1 = "Preventive"
    CATEGORY_2 = "Detective"

    CHOICES = (
        (CATEGORY_1, "Preventive"),
        (CATEGORY_2, "Detective"),
    )
