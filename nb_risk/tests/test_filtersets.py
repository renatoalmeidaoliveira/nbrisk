"""
FilterSet tests for nb_risk.
"""

from django.test import TestCase
from dcim.models import Platform

from nb_risk.models import ThreatSource, Vulnerability, CPEMapping
from nb_risk.filtersets import (
    ThreatSourceFilterSet,
    VulnerabilityFilterSet,
    CPEMappingFilterSet,
)
from nb_risk.choices import ThreatTypeChoices, CapabilityChoices


class ThreatSourceFilterSetTestCase(TestCase):

    def setUp(self):
        ThreatSource.objects.create(
            name='Nation State',
            threat_type=ThreatTypeChoices.ADVERSARIAL,
            capability=CapabilityChoices.HIGH,
        )
        ThreatSource.objects.create(
            name='Insider',
            threat_type=ThreatTypeChoices.ACCIDENTAL,
            capability=CapabilityChoices.LOW,
        )

    def test_filter_by_name(self):
        fs = ThreatSourceFilterSet({'name': 'Nation'}, queryset=ThreatSource.objects.all())
        self.assertEqual(fs.qs.count(), 1)

    def test_filter_by_threat_type(self):
        fs = ThreatSourceFilterSet(
            {'threat_type': [ThreatTypeChoices.ADVERSARIAL]},
            queryset=ThreatSource.objects.all(),
        )
        self.assertEqual(fs.qs.count(), 1)


class VulnerabilityFilterSetTestCase(TestCase):

    def setUp(self):
        Vulnerability.objects.create(
            name='CVE-2021-44228',
            cve='CVE-2021-44228',
            in_kev=True,
        )
        Vulnerability.objects.create(
            name='CVE-2022-1234',
            cve='CVE-2022-1234',
            in_kev=False,
        )

    def test_filter_by_cve(self):
        fs = VulnerabilityFilterSet(
            {'cve': 'CVE-2021-44228'},
            queryset=Vulnerability.objects.all(),
        )
        self.assertEqual(fs.qs.count(), 1)

    def test_filter_in_kev_true(self):
        fs = VulnerabilityFilterSet(
            {'in_kev': True},
            queryset=Vulnerability.objects.all(),
        )
        self.assertEqual(fs.qs.count(), 1)
        self.assertEqual(fs.qs.first().cve, 'CVE-2021-44228')

    def test_filter_in_kev_false(self):
        fs = VulnerabilityFilterSet(
            {'in_kev': False},
            queryset=Vulnerability.objects.all(),
        )
        self.assertEqual(fs.qs.count(), 1)
        self.assertEqual(fs.qs.first().cve, 'CVE-2022-1234')


class CPEMappingFilterSetTestCase(TestCase):

    def setUp(self):
        self.platform = Platform.objects.create(name='NX-OS', slug='nx-os')
        CPEMapping.objects.create(
            platform=self.platform,
            cpe_part='o',
            cpe_vendor='cisco',
            cpe_product='nx-os',
            verified=True,
        )
        platform2 = Platform.objects.create(name='Junos', slug='junos')
        CPEMapping.objects.create(
            platform=platform2,
            cpe_part='o',
            cpe_vendor='juniper',
            cpe_product='junos',
            verified=False,
        )

    def test_filter_by_vendor(self):
        fs = CPEMappingFilterSet(
            {'cpe_vendor': 'cisco'},
            queryset=CPEMapping.objects.all(),
        )
        self.assertEqual(fs.qs.count(), 1)

    def test_filter_by_verified(self):
        fs = CPEMappingFilterSet(
            {'verified': True},
            queryset=CPEMapping.objects.all(),
        )
        self.assertEqual(fs.qs.count(), 1)
        self.assertEqual(fs.qs.first().cpe_vendor, 'cisco')

    def test_filter_by_platform(self):
        fs = CPEMappingFilterSet(
            {'platform_id': [self.platform.pk]},
            queryset=CPEMapping.objects.all(),
        )
        self.assertEqual(fs.qs.count(), 1)
