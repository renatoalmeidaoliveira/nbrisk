from django.test import TestCase

from utilities.testing import ChangeLoggedFilterSetTests

from nb_risk.models import ThreatSource
from nb_risk.filters import ThreatSourceFilterSet
from nb_risk import choices


class ThreatSourceFilterTestCase(TestCase, ChangeLoggedFilterSetTests):
    queryset = ThreatSource.objects.all()
    filterset = ThreatSourceFilterSet

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

    def test_name_none(self):
        params = {"name": ["None"]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 0)

    def test_name(self):
        params = {"name": ["ThreatSource 1", "ThreatSource 2"]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 2)

    def test_names(self):
        params = {"name__icontains": ["ThreatSource"]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)

    def test_capability(self):
        params = {"capability": [choices.CapabilityChoices.CAPABILITY_1]}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 3)

    def test_capability_none(self):
        params = {"capability": choices.CapabilityChoices.CAPABILITY_2}
        self.assertEqual(self.filterset(params, self.queryset).qs.count(), 0)
