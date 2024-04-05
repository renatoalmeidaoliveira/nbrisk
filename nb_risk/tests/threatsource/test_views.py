from utilities.testing import ViewTestCases, create_tags

from nb_risk.tests.custom import ModelViewTestCase
from nb_risk.models import ThreatSource
from nb_risk import choices


class ControlViewTestCase(
    ModelViewTestCase,
    ViewTestCases.GetObjectViewTestCase,
    ViewTestCases.CreateObjectViewTestCase,
    ViewTestCases.EditObjectViewTestCase,
    ViewTestCases.DeleteObjectViewTestCase,
    ViewTestCases.ListObjectsViewTestCase,
    ViewTestCases.GetObjectChangelogViewTestCase,
    ViewTestCases.BulkImportObjectsViewTestCase,
    ViewTestCases.BulkDeleteObjectsViewTestCase,
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

        cls.form_data = {
            "name": "ThreatSource X",
            "threat_type": choices.ThreatTypeChoices.THREAT_TYPE_1,
            "capability": choices.CapabilityChoices.CAPABILITY_1,
            "description": "A new threat source",
        }

        cls.csv_data = (
            "name,threat_type,capability,description",
            "ThreatSource 4,ADVERSARIAL,Very High,Test Profile 1",
            "ThreatSource 5,ADVERSARIAL,Very High,Test Profile 2",
            "ThreatSource 6,ADVERSARIAL,Very High,Test Profile 3",
        )

        cls.csv_update_data = (
            "id,name,description",
            f"{t_sources[0].pk},New Test Service 1,Test Profile 1",
            f"{t_sources[1].pk},New Test Service 2,Test Profile 2",
        )

        maxDiff = None
