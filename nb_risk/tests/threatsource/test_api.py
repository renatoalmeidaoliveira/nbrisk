from utilities.testing import APIViewTestCases

from nb_risk.tests.custom import APITestCase
from nb_risk.models import ThreatSource
from nb_risk import choices

class ApplicationAPITestCase(
    APITestCase,
    APIViewTestCases.GetObjectViewTestCase,
    APIViewTestCases.ListObjectsViewTestCase,
    APIViewTestCases.CreateObjectViewTestCase,
    APIViewTestCases.UpdateObjectViewTestCase,
    APIViewTestCases.DeleteObjectViewTestCase,
):
    model = ThreatSource

    @classmethod
    def setUpTestData(cls):
        t_sources = (
            ThreatSource(
                name="ThreatSource 1",
                threat_type=choices.ThreatTypeChoices.THREAT_TYPE_1,
                capability=choices.CapabilityChoices.CAPABILITY_1,
                description="A test threat source",
            ),
            ThreatSource(
                name="ThreatSource 2",
                threat_type=choices.ThreatTypeChoices.THREAT_TYPE_1,
                capability=choices.CapabilityChoices.CAPABILITY_1,
                description="Another test threat source",
            ),
            ThreatSource(
                name="ThreatSource 3",
                threat_type=choices.ThreatTypeChoices.THREAT_TYPE_1,
                capability=choices.CapabilityChoices.CAPABILITY_1,
                description="Yet another test threat source",
            ),
        )
        ThreatSource.objects.bulk_create(t_sources)

        cls.create_data = [ 
            {"name": "ThreatSource X","threat_type": choices.ThreatTypeChoices.THREAT_TYPE_1,"capability": choices.CapabilityChoices.CAPABILITY_1, "description": "A new threat source", },
            {"name": "ThreatSource Y","threat_type": choices.ThreatTypeChoices.THREAT_TYPE_1,"capability": choices.CapabilityChoices.CAPABILITY_1, "description": "Another new threat source", },
        ]

        cls.brief_fields = ['display', 'id', 'name', 'url']