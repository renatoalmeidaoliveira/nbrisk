"""
Tests for CISA KEV and EPSS sync logic.

Uses unittest.mock to avoid live network calls.
"""

import json
from datetime import date
from unittest.mock import patch, MagicMock

from django.test import TestCase

from nb_risk.models import Vulnerability
from nb_risk.kev import (
    fetch_kev_catalog,
    sync_kev_to_db,
    enrich_cve_results,
    get_kev_set,
)
from nb_risk.epss import (
    fetch_epss_scores,
    sync_epss_to_db,
    enrich_cve_results as enrich_epss,
)

MOCK_KEV_RESPONSE = {
    "title": "CISA Known Exploited Vulnerabilities Catalog",
    "catalogVersion": "2026.05.20",
    "dateReleased": "2026-05-20T00:00:00.000Z",
    "count": 2,
    "vulnerabilities": [
        {
            "cveID": "CVE-2021-44228",
            "vendorProject": "Apache",
            "product": "Log4j2",
            "vulnerabilityName": "Apache Log4j2 RCE",
            "dateAdded": "2021-12-10",
            "shortDescription": "Log4Shell",
            "requiredAction": "Apply updates per vendor instructions.",
            "dueDate": "2021-12-24",
            "knownRansomwareCampaignUse": "Known",
        },
        {
            "cveID": "CVE-2022-1234",
            "vendorProject": "Cisco",
            "product": "NX-OS",
            "vulnerabilityName": "Test CVE",
            "dateAdded": "2022-06-01",
            "shortDescription": "Test",
            "requiredAction": "Apply patch.",
            "dueDate": "2022-06-15",
            "knownRansomwareCampaignUse": "Unknown",
        },
    ],
}

MOCK_EPSS_RESPONSE = {
    "status": "OK",
    "status-code": 200,
    "total": 2,
    "data": [
        {"cve": "CVE-2021-44228", "epss": "0.943580000", "percentile": "0.999630000", "date": "2026-05-20"},
        {"cve": "CVE-2022-1234", "epss": "0.012300000", "percentile": "0.750000000", "date": "2026-05-20"},
    ],
}


class FetchKEVCatalogTestCase(TestCase):

    @patch('nb_risk.kev.requests.get')
    def test_fetch_success(self, mock_get):
        mock_get.return_value.status_code = 200
        mock_get.return_value.json.return_value = MOCK_KEV_RESPONSE
        mock_get.return_value.raise_for_status = MagicMock()

        catalog = fetch_kev_catalog()
        self.assertEqual(len(catalog), 2)
        self.assertIn('CVE-2021-44228', catalog)
        self.assertEqual(catalog['CVE-2021-44228']['vendorProject'], 'Apache')

    @patch('nb_risk.kev.requests.get')
    def test_fetch_failure_returns_empty(self, mock_get):
        mock_get.side_effect = Exception("Network error")
        catalog = fetch_kev_catalog()
        self.assertEqual(catalog, {})


class SyncKEVToDBTestCase(TestCase):

    def setUp(self):
        self.vuln1 = Vulnerability.objects.create(
            name='CVE-2021-44228',
            cve='CVE-2021-44228',
        )
        self.vuln2 = Vulnerability.objects.create(
            name='CVE-2022-1234',
            cve='CVE-2022-1234',
        )
        self.vuln3 = Vulnerability.objects.create(
            name='CVE-2099-9999',
            cve='CVE-2099-9999',
        )

    @patch('nb_risk.kev.requests.get')
    def test_sync_marks_kev_vulnerabilities(self, mock_get):
        mock_get.return_value.json.return_value = MOCK_KEV_RESPONSE
        mock_get.return_value.raise_for_status = MagicMock()

        updated, cleared, total = sync_kev_to_db()
        self.assertEqual(updated, 2)
        self.assertEqual(total, 2)

        self.vuln1.refresh_from_db()
        self.assertTrue(self.vuln1.in_kev)
        self.assertEqual(self.vuln1.kev_ransomware_use, 'Known')
        self.assertEqual(self.vuln1.kev_date_added, date(2021, 12, 10))

    @patch('nb_risk.kev.requests.get')
    def test_sync_clears_stale_kev_flags(self, mock_get):
        # Pre-mark vuln3 as KEV
        Vulnerability.objects.filter(pk=self.vuln3.pk).update(in_kev=True)

        mock_get.return_value.json.return_value = MOCK_KEV_RESPONSE
        mock_get.return_value.raise_for_status = MagicMock()

        updated, cleared, total = sync_kev_to_db()
        self.assertEqual(cleared, 1)

        self.vuln3.refresh_from_db()
        self.assertFalse(self.vuln3.in_kev)

    @patch('nb_risk.kev.requests.get')
    def test_enrich_cve_results(self, mock_get):
        # Pre-populate DB with KEV data
        Vulnerability.objects.filter(pk=self.vuln1.pk).update(in_kev=True)

        cve_list = [
            {'id': 'CVE-2021-44228'},
            {'id': 'CVE-2022-9999'},
        ]
        result = enrich_cve_results(cve_list)
        self.assertTrue(result[0]['in_kev'])
        self.assertFalse(result[1]['in_kev'])


class FetchEPSSScoresTestCase(TestCase):

    @patch('nb_risk.epss.requests.get')
    def test_fetch_success(self, mock_get):
        mock_get.return_value.json.return_value = MOCK_EPSS_RESPONSE
        mock_get.return_value.raise_for_status = MagicMock()

        scores = fetch_epss_scores(['CVE-2021-44228', 'CVE-2022-1234'])
        self.assertEqual(len(scores), 2)
        self.assertAlmostEqual(scores['CVE-2021-44228']['epss'], 0.94358, places=4)
        self.assertAlmostEqual(scores['CVE-2022-1234']['epss'], 0.0123, places=4)

    @patch('nb_risk.epss.requests.get')
    def test_fetch_failure_returns_empty(self, mock_get):
        mock_get.side_effect = Exception("Network error")
        scores = fetch_epss_scores(['CVE-2021-44228'])
        self.assertEqual(scores, {})


class SyncEPSSToDBTestCase(TestCase):

    def setUp(self):
        self.vuln = Vulnerability.objects.create(
            name='CVE-2021-44228',
            cve='CVE-2021-44228',
        )

    @patch('nb_risk.epss.requests.get')
    def test_sync_updates_epss_fields(self, mock_get):
        mock_get.return_value.json.return_value = MOCK_EPSS_RESPONSE
        mock_get.return_value.raise_for_status = MagicMock()

        updated, total = sync_epss_to_db()
        self.assertEqual(updated, 1)
        self.assertEqual(total, 1)

        self.vuln.refresh_from_db()
        self.assertAlmostEqual(float(self.vuln.epss_score), 0.94358, places=4)
        self.assertEqual(self.vuln.epss_date, date(2026, 5, 20))

    @patch('nb_risk.epss.requests.get')
    def test_enrich_cve_results_with_epss(self, mock_get):
        mock_get.return_value.json.return_value = MOCK_EPSS_RESPONSE
        mock_get.return_value.raise_for_status = MagicMock()

        cve_list = [{'id': 'CVE-2021-44228'}, {'id': 'CVE-2022-1234'}]
        result = enrich_epss(cve_list)
        self.assertAlmostEqual(result[0]['epss_score'], 0.94358, places=4)
        self.assertAlmostEqual(result[1]['epss_score'], 0.0123, places=4)
