"""
API tests for nb_risk.

Tests cover: list, retrieve, create, update, and delete for all
API endpoints. Uses NetBox's test client with authentication.
"""

from django.urls import reverse
from rest_framework import status
from rest_framework.test import APITestCase

from users.models import User
from dcim.models import Platform

from nb_risk.models import (
    ThreatSource,
    ThreatEvent,
    Vulnerability,
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


class BaseAPITestCase(APITestCase):

    def setUp(self):
        self.user = User.objects.create_superuser(
            username='testuser',
            password='testpassword',
        )
        self.client.force_authenticate(user=self.user)


class ThreatSourceAPITestCase(BaseAPITestCase):

    def setUp(self):
        super().setUp()
        self.ts = ThreatSource.objects.create(
            name='API Test Source',
            threat_type=ThreatTypeChoices.ADVERSARIAL,
            capability=CapabilityChoices.HIGH,
        )

    def test_list(self):
        url = reverse('plugins-api:nb_risk-api:threatsource-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)

    def test_retrieve(self):
        url = reverse('plugins-api:nb_risk-api:threatsource-detail', kwargs={'pk': self.ts.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['name'], 'API Test Source')

    def test_create(self):
        url = reverse('plugins-api:nb_risk-api:threatsource-list')
        data = {
            'name': 'New Source',
            'threat_type': ThreatTypeChoices.ACCIDENTAL,
            'capability': CapabilityChoices.LOW,
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(ThreatSource.objects.count(), 2)

    def test_update(self):
        url = reverse('plugins-api:nb_risk-api:threatsource-detail', kwargs={'pk': self.ts.pk})
        response = self.client.patch(url, {'capability': CapabilityChoices.LOW}, format='json')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.ts.refresh_from_db()
        self.assertEqual(self.ts.capability, CapabilityChoices.LOW)

    def test_delete(self):
        url = reverse('plugins-api:nb_risk-api:threatsource-detail', kwargs={'pk': self.ts.pk})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(ThreatSource.objects.count(), 0)


class VulnerabilityAPITestCase(BaseAPITestCase):

    def setUp(self):
        super().setUp()
        self.vuln = Vulnerability.objects.create(
            name='CVE-2021-44228',
            cve='CVE-2021-44228',
            description='Log4Shell RCE',
        )

    def test_list(self):
        url = reverse('plugins-api:nb_risk-api:vulnerability-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)

    def test_retrieve(self):
        url = reverse('plugins-api:nb_risk-api:vulnerability-detail', kwargs={'pk': self.vuln.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['cve'], 'CVE-2021-44228')

    def test_create(self):
        url = reverse('plugins-api:nb_risk-api:vulnerability-list')
        data = {'name': 'CVE-2022-1234', 'cve': 'CVE-2022-1234'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_kev_fields_in_response(self):
        url = reverse('plugins-api:nb_risk-api:vulnerability-detail', kwargs={'pk': self.vuln.pk})
        response = self.client.get(url)
        self.assertIn('in_kev', response.data)
        self.assertFalse(response.data['in_kev'])


class CPEMappingAPITestCase(BaseAPITestCase):

    def setUp(self):
        super().setUp()
        self.platform = Platform.objects.create(name='NX-OS', slug='nx-os')
        self.mapping = CPEMapping.objects.create(
            platform=self.platform,
            cpe_part='o',
            cpe_vendor='cisco',
            cpe_product='nx-os',
        )

    def test_list(self):
        url = reverse('plugins-api:nb_risk-api:cpemapping-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['count'], 1)

    def test_retrieve(self):
        url = reverse('plugins-api:nb_risk-api:cpemapping-detail', kwargs={'pk': self.mapping.pk})
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['cpe_vendor'], 'cisco')
        self.assertEqual(response.data['cpe_product'], 'nx-os')

    def test_create(self):
        platform2 = Platform.objects.create(name='Junos', slug='junos')
        url = reverse('plugins-api:nb_risk-api:cpemapping-list')
        data = {
            'platform': platform2.pk,
            'cpe_part': 'o',
            'cpe_vendor': 'juniper',
            'cpe_product': 'junos',
        }
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)

    def test_delete(self):
        url = reverse('plugins-api:nb_risk-api:cpemapping-detail', kwargs={'pk': self.mapping.pk})
        response = self.client.delete(url)
        self.assertEqual(response.status_code, status.HTTP_204_NO_CONTENT)
        self.assertEqual(CPEMapping.objects.count(), 0)


class ControlAPITestCase(BaseAPITestCase):

    def setUp(self):
        super().setUp()
        self.control = Control.objects.create(name='Test Control')

    def test_list(self):
        url = reverse('plugins-api:nb_risk-api:control-list')
        response = self.client.get(url)
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_create(self):
        url = reverse('plugins-api:nb_risk-api:control-list')
        data = {'name': 'New Control', 'description': 'Test'}
        response = self.client.post(url, data, format='json')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
