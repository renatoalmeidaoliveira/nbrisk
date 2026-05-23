"""
Model tests for nb_risk.

Tests cover: creation, __str__, get_absolute_url, validation,
unique constraints, and the CPEMapping.build_cpe() helper.
"""

from django.core.exceptions import ValidationError
from django.test import TestCase

from dcim.models import DeviceType, Manufacturer, Platform

from nb_risk.models import (
    ThreatSource,
    ThreatEvent,
    Vulnerability,
    VulnerabilityAssignment,
    Risk,
    Control,
    CPEMapping,
)
from nb_risk.choices import (
    ThreatTypeChoices,
    CapabilityChoices,
    RelevanceChoices,
    LikelihoodChoices,
)


class ThreatSourceTestCase(TestCase):

    def setUp(self):
        self.ts = ThreatSource.objects.create(
            name='Test Threat Source',
            threat_type=ThreatTypeChoices.ADVERSARIAL,
            capability=CapabilityChoices.HIGH,
        )

    def test_create(self):
        self.assertIsInstance(self.ts, ThreatSource)
        self.assertEqual(str(self.ts), 'Test Threat Source')

    def test_unique_name(self):
        with self.assertRaises(Exception):
            ThreatSource.objects.create(name='Test Threat Source')

    def test_get_absolute_url(self):
        url = self.ts.get_absolute_url()
        self.assertIn(str(self.ts.pk), url)


class ThreatEventTestCase(TestCase):

    def setUp(self):
        self.ts = ThreatSource.objects.create(
            name='Source',
            threat_type=ThreatTypeChoices.ADVERSARIAL,
            capability=CapabilityChoices.MEDIUM,
        )
        self.te = ThreatEvent.objects.create(
            name='Test Event',
            threat_source=self.ts,
            relevance=RelevanceChoices.RELEVANT,
            likelihood=LikelihoodChoices.MEDIUM,
        )

    def test_create(self):
        self.assertIsInstance(self.te, ThreatEvent)
        self.assertEqual(str(self.te), 'Test Event')

    def test_threat_source_relation(self):
        self.assertEqual(self.te.threat_source, self.ts)

    def test_get_absolute_url(self):
        url = self.te.get_absolute_url()
        self.assertIn(str(self.te.pk), url)


class VulnerabilityTestCase(TestCase):

    def setUp(self):
        self.vuln = Vulnerability.objects.create(
            name='CVE-2021-44228',
            cve='CVE-2021-44228',
            description='Log4Shell',
        )

    def test_create(self):
        self.assertIsInstance(self.vuln, Vulnerability)
        self.assertEqual(str(self.vuln), 'CVE-2021-44228')

    def test_unique_name(self):
        with self.assertRaises(Exception):
            Vulnerability.objects.create(name='CVE-2021-44228')

    def test_kev_fields_default(self):
        self.assertFalse(self.vuln.in_kev)
        self.assertIsNone(self.vuln.kev_date_added)
        self.assertEqual(self.vuln.kev_ransomware_use, '')

    def test_epss_fields_default(self):
        self.assertIsNone(self.vuln.epss_score)
        self.assertIsNone(self.vuln.epss_percentile)
        self.assertIsNone(self.vuln.epss_date)

    def test_get_absolute_url(self):
        url = self.vuln.get_absolute_url()
        self.assertIn(str(self.vuln.pk), url)


class RiskTestCase(TestCase):

    def setUp(self):
        ts = ThreatSource.objects.create(
            name='Risk Source',
            threat_type=ThreatTypeChoices.ADVERSARIAL,
            capability=CapabilityChoices.LOW,
        )
        te = ThreatEvent.objects.create(
            name='Risk Event',
            threat_source=ts,
            relevance=RelevanceChoices.RELEVANT,
            likelihood=LikelihoodChoices.LOW,
        )
        self.risk = Risk.objects.create(
            name='Test Risk',
            threat_event=te,
        )

    def test_create(self):
        self.assertIsInstance(self.risk, Risk)
        self.assertEqual(str(self.risk), 'Test Risk')


class ControlTestCase(TestCase):

    def setUp(self):
        self.control = Control.objects.create(name='Test Control')

    def test_create(self):
        self.assertIsInstance(self.control, Control)
        self.assertEqual(str(self.control), 'Test Control')


class CPEMappingTestCase(TestCase):

    def setUp(self):
        self.platform = Platform.objects.create(name='NX-OS', slug='nx-os')
        self.mapping = CPEMapping.objects.create(
            platform=self.platform,
            cpe_part='o',
            cpe_vendor='cisco',
            cpe_product='nx-os',
            cpe_target_sw='nexus_9000_series',
        )

    def test_create(self):
        self.assertIsInstance(self.mapping, CPEMapping)

    def test_str(self):
        self.assertIn('cisco', str(self.mapping))
        self.assertIn('nx-os', str(self.mapping))

    def test_build_cpe_with_version(self):
        cpe = self.mapping.build_cpe('16.1\\(4h\\)')
        self.assertEqual(
            cpe,
            'cpe:2.3:o:cisco:nx-os:16.1\\(4h\\):*:*:*:*:nexus_9000_series:*:*'
        )

    def test_build_cpe_wildcard(self):
        cpe = self.mapping.build_cpe()
        self.assertIn('*', cpe)
        self.assertIn('cisco', cpe)

    def test_validation_requires_platform_or_device_type(self):
        mapping = CPEMapping(
            cpe_part='o',
            cpe_vendor='cisco',
            cpe_product='nx-os',
        )
        with self.assertRaises(ValidationError):
            mapping.clean()

    def test_validation_rejects_both_platform_and_device_type(self):
        manufacturer = Manufacturer.objects.create(name='Cisco', slug='cisco')
        dt = DeviceType.objects.create(
            manufacturer=manufacturer,
            model='Nexus 9396PX',
            slug='nexus-9396px',
        )
        mapping = CPEMapping(
            platform=self.platform,
            device_type=dt,
            cpe_part='o',
            cpe_vendor='cisco',
            cpe_product='nx-os',
        )
        with self.assertRaises(ValidationError):
            mapping.clean()

    def test_device_type_mapping(self):
        manufacturer = Manufacturer.objects.create(name='Juniper', slug='juniper')
        dt = DeviceType.objects.create(
            manufacturer=manufacturer,
            model='EX4300',
            slug='ex4300',
        )
        mapping = CPEMapping.objects.create(
            device_type=dt,
            cpe_part='o',
            cpe_vendor='juniper',
            cpe_product='junos',
        )
        self.assertEqual(mapping.cpe_vendor, 'juniper')
        cpe = mapping.build_cpe('21.4R3')
        self.assertIn('juniper', cpe)
        self.assertIn('junos', cpe)
        self.assertIn('21.4R3', cpe)
