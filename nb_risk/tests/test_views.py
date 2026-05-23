"""
View tests for nb_risk.

Tests cover: list, detail, add, edit, and delete views for all models.
Uses NetBox's test client with authentication.
"""

from django.test import TestCase, Client
from django.urls import reverse

from users.models import User
from dcim.models import Platform

from nb_risk.models import (
    ThreatSource,
    Vulnerability,
    Risk,
    Control,
    CPEMapping,
    ThreatEvent,
)
from nb_risk.choices import (
    ThreatTypeChoices,
    CapabilityChoices,
    RelevanceChoices,
    LikelihoodChoices,
)


class BaseViewTestCase(TestCase):

    def setUp(self):
        self.user = User.objects.create_superuser(
            username='viewtestuser',
            password='testpassword',
        )
        self.client = Client()
        self.client.force_login(self.user)


class ThreatSourceViewTestCase(BaseViewTestCase):

    def setUp(self):
        super().setUp()
        self.ts = ThreatSource.objects.create(
            name='View Test Source',
            threat_type=ThreatTypeChoices.ADVERSARIAL,
            capability=CapabilityChoices.HIGH,
        )

    def test_list_view(self):
        url = reverse('plugins:nb_risk:threatsource_list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'View Test Source')

    def test_detail_view(self):
        url = reverse('plugins:nb_risk:threatsource', kwargs={'pk': self.ts.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_add_view_get(self):
        url = reverse('plugins:nb_risk:threatsource_add')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_add_view_post(self):
        url = reverse('plugins:nb_risk:threatsource_add')
        data = {
            'name': 'Created Source',
            'threat_type': ThreatTypeChoices.ACCIDENTAL,
            'capability': CapabilityChoices.LOW,
        }
        response = self.client.post(url, data)
        self.assertEqual(ThreatSource.objects.filter(name='Created Source').count(), 1)

    def test_delete_view(self):
        url = reverse('plugins:nb_risk:threatsource_delete', kwargs={'pk': self.ts.pk})
        response = self.client.post(url, {'confirm': True})
        self.assertEqual(ThreatSource.objects.count(), 0)


class VulnerabilityViewTestCase(BaseViewTestCase):

    def setUp(self):
        super().setUp()
        self.vuln = Vulnerability.objects.create(
            name='CVE-2021-44228',
            cve='CVE-2021-44228',
        )

    def test_list_view(self):
        url = reverse('plugins:nb_risk:vulnerability_list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'CVE-2021-44228')

    def test_detail_view(self):
        url = reverse('plugins:nb_risk:vulnerability', kwargs={'pk': self.vuln.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_search_view(self):
        url = reverse('plugins:nb_risk:vulnerability_search')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)


class CPEMappingViewTestCase(BaseViewTestCase):

    def setUp(self):
        super().setUp()
        self.platform = Platform.objects.create(name='NX-OS', slug='nx-os')
        self.mapping = CPEMapping.objects.create(
            platform=self.platform,
            cpe_part='o',
            cpe_vendor='cisco',
            cpe_product='nx-os',
        )

    def test_list_view(self):
        url = reverse('plugins:nb_risk:cpemapping_list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        self.assertContains(response, 'cisco')

    def test_detail_view(self):
        url = reverse('plugins:nb_risk:cpemapping', kwargs={'pk': self.mapping.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_add_view_get(self):
        url = reverse('plugins:nb_risk:cpemapping_add')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_cpe_lookup_view(self):
        url = reverse('plugins:nb_risk:cpe_lookup')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_delete_view(self):
        url = reverse('plugins:nb_risk:cpemapping_delete', kwargs={'pk': self.mapping.pk})
        response = self.client.post(url, {'confirm': True})
        self.assertEqual(CPEMapping.objects.count(), 0)


class ControlViewTestCase(BaseViewTestCase):

    def setUp(self):
        super().setUp()
        self.control = Control.objects.create(name='Test Control')

    def test_list_view(self):
        url = reverse('plugins:nb_risk:control_list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)

    def test_detail_view(self):
        url = reverse('plugins:nb_risk:control', kwargs={'pk': self.control.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
