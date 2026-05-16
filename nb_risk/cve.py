from netbox.plugins.utils import get_plugin_config
from dcim.models import Device, Site, DeviceType
from tenancy.models import Tenant
from virtualization.models import VirtualMachine

from utilities.views import ViewTab, register_model_view
from django.contrib.contenttypes.models import ContentType
from django.shortcuts import get_object_or_404
from django.conf import settings

from django.views.generic import View
from django.shortcuts import redirect, render

from utilities.views import ObjectPermissionRequiredMixin
from utilities.permissions import get_permission_for_model
from netbox.views import generic

import logging
import re
import requests

logger = logging.getLogger(__name__)

from . import forms, models, tables

NVD_CVE_URI = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_CPE_URI = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


# Vulnerability Search Views


class VulnerabilitySearchView(ObjectPermissionRequiredMixin, View):
    queryset = models.Vulnerability.objects.all()
    template_name = "nb_risk/vulnerability_search.html"
    tab = None
    filterset_form = forms.VulnerabilitySearchFilterForm

    def get_required_permission(self):
        return get_permission_for_model(self.queryset.model, "view")

    def get(self, request, **kwargs):
        cves = get_cves(request)
        table = tables.CveTable(cves)

        return render(
            request,
            self.template_name,
            {
                "tab": self.tab,
                "cves": cves,
                "filter_form": self.filterset_form,
                "table": table,
            },
        )


def _get_nvd_headers():
    """Return headers for NVD API requests, including API key if configured."""
    api_key = get_plugin_config("nb_risk", "nvd_api_key")
    headers = {}
    if api_key:
        headers["apiKey"] = api_key
    return headers


def _get_proxies():
    """
    Return proxy settings for requests, using NetBox's own HTTP_PROXIES
    setting from configuration.py. Falls back to the plugin-level 'proxies'
    setting for backwards compatibility, then to no proxy.
    """
    # Prefer NetBox's built-in HTTP_PROXIES (set in configuration.py)
    netbox_proxies = getattr(settings, 'HTTP_PROXIES', None)
    if netbox_proxies:
        return netbox_proxies
    # Fall back to plugin-level setting for backwards compatibility
    return get_plugin_config("nb_risk", "proxies") or {}


def get_query(request):
    if request.GET.get("cpe") is not None:
        return {
            "URI": NVD_CPE_URI,
            "payload": {"cpeName": request.GET.get("cpe")},
            "type": "cpe",
        }
    elif request.GET.get("cve") is not None:
        return {
            "URI": NVD_CVE_URI,
            "payload": {"cveId": request.GET.get("cve")},
            "type": "cve",
        }
    elif request.GET.get("keyword") is not None:
        return {
            "URI": NVD_CVE_URI,
            "payload": {"keywordSearch": request.GET.get("keyword")},
            "type": "cve",
        }
    elif request.GET.get("device_type") is not None:
        device_type_id = request.GET.get("device_type")
        device_type = DeviceType.objects.get(id=device_type_id)
        manufacturer = device_type.manufacturer.name
        product = device_type.model
        version = request.GET.get("version") or "-"
        part = request.GET.get("part") or "h"
        cpe_string = f"cpe:2.3:{part}:{manufacturer}:{product}:{version}:*:*:*:*:*:*:*"
        # Search CVEs by CPE name rather than the CPE registry
        return {
            "URI": NVD_CVE_URI,
            "payload": {"cpeName": cpe_string},
            "type": "cve",
        }
    return None


def _parse_cvss(cve_entry):
    """
    Extract CVSS metrics from a CVE entry, preferring CVSSv2 for field
    compatibility with the Vulnerability model, but falling back to
    CVSSv3.x and CVSSv4.0 base scores when v2 data is absent.
    """
    metrics = cve_entry.get("metrics", {})
    result = {
        "accessVector": "",
        "accessComplexity": "",
        "authentication": "",
        "confidentialityImpact": "",
        "integrityImpact": "",
        "availabilityImpact": "",
        "baseScore": "",
        "cvssVersion": "",
    }

    # CVSSv2 — full field mapping
    if "cvssMetricV2" in metrics:
        data = metrics["cvssMetricV2"][0]["cvssData"]
        result.update({
            "accessVector": data.get("accessVector", ""),
            "accessComplexity": data.get("accessComplexity", ""),
            "authentication": data.get("authentication", ""),
            "confidentialityImpact": data.get("confidentialityImpact", ""),
            "integrityImpact": data.get("integrityImpact", ""),
            "availabilityImpact": data.get("availabilityImpact", ""),
            "baseScore": data.get("baseScore", ""),
            "cvssVersion": "2.0",
        })
        return result

    # CVSSv3.1 — partial mapping (no authentication field in v3)
    if "cvssMetricV31" in metrics:
        data = metrics["cvssMetricV31"][0]["cvssData"]
        result.update({
            "accessVector": data.get("attackVector", ""),
            "accessComplexity": data.get("attackComplexity", ""),
            "authentication": "",  # not present in v3
            "confidentialityImpact": data.get("confidentialityImpact", ""),
            "integrityImpact": data.get("integrityImpact", ""),
            "availabilityImpact": data.get("availabilityImpact", ""),
            "baseScore": data.get("baseScore", ""),
            "cvssVersion": "3.1",
        })
        return result

    # CVSSv3.0
    if "cvssMetricV30" in metrics:
        data = metrics["cvssMetricV30"][0]["cvssData"]
        result.update({
            "accessVector": data.get("attackVector", ""),
            "accessComplexity": data.get("attackComplexity", ""),
            "authentication": "",
            "confidentialityImpact": data.get("confidentialityImpact", ""),
            "integrityImpact": data.get("integrityImpact", ""),
            "availabilityImpact": data.get("availabilityImpact", ""),
            "baseScore": data.get("baseScore", ""),
            "cvssVersion": "3.0",
        })
        return result

    # CVSSv4.0 — base score only, field names differ significantly
    if "cvssMetricV40" in metrics:
        data = metrics["cvssMetricV40"][0]["cvssData"]
        result.update({
            "accessVector": data.get("attackVector", ""),
            "accessComplexity": data.get("attackComplexity", ""),
            "confidentialityImpact": data.get("vulnConfidentialityImpact", ""),
            "integrityImpact": data.get("vulnIntegrityImpact", ""),
            "availabilityImpact": data.get("vulnAvailabilityImpact", ""),
            "baseScore": data.get("baseScore", ""),
            "cvssVersion": "4.0",
        })
        return result

    return result


def _parse_cve_entries(entries, return_url):
    """Parse a list of NVD CVE vulnerability entries into table-ready dicts."""
    output = []
    for entry in entries:
        cve_data = entry.get("cve", {})
        cve_id = cve_data.get("id", "")

        description = ""
        for desc in cve_data.get("descriptions", []):
            if desc.get("lang") == "en":
                description = desc["value"]
                break

        cvss = _parse_cvss(cve_data)

        output.append({
            "id": cve_id,
            "description": description,
            "return_url": return_url,
            **cvss,
        })
    return output


def _parse_cpe_entries(entries, return_url):
    """
    Parse NVD CPE entries. The CPE endpoint returns products, not CVEs.
    For each CPE found, perform a follow-up CVE lookup by cpeName so
    the results table still shows CVEs.
    """
    proxies = _get_proxies()
    headers = _get_nvd_headers()
    output = []

    for entry in entries:
        cpe_name = entry.get("cpe", {}).get("cpeName", "")
        if not cpe_name:
            continue
        try:
            r = requests.get(
                NVD_CVE_URI,
                params={"cpeName": cpe_name},
                headers=headers,
                proxies=proxies,
                timeout=15,
            )
            r.raise_for_status()
            vulns = r.json().get("vulnerabilities", [])
            output.extend(_parse_cve_entries(vulns, return_url))
        except Exception as e:
            logger.warning("CVE lookup for CPE %s failed: %s", cpe_name, e)

    return output


def get_cves(request):
    query = get_query(request)
    if query is None:
        return []

    try:
        proxies = _get_proxies()
        headers = _get_nvd_headers()
        return_url = f"{request.path}?{request.META['QUERY_STRING']}"

        r = requests.get(
            query["URI"],
            params=query["payload"],
            headers=headers,
            proxies=proxies,
            timeout=15,
        )
        r.raise_for_status()
        data = r.json()

        if query["type"] == "cpe":
            entries = data.get("products", [])
            return _parse_cpe_entries(entries, return_url)
        else:
            entries = data.get("vulnerabilities", [])
            return _parse_cve_entries(entries, return_url)

    except Exception as e:
        logger.error("NVD API request failed: %s", e)
        return []


# ─────────────────────────────────────────────────────────────────────────────
# Software CVE Integration (netbox_software_tracker)
# ─────────────────────────────────────────────────────────────────────────────

SW_TRACKER_CF = "software_version"  # custom field name used by netbox_software_tracker


def _normalize_cpe_component(value):
    """
    Normalize a string to a CPE 2.3 component:
    - lowercase
    - replace spaces, hyphens, and slashes with underscores
    - strip any remaining non-alphanumeric/underscore/dot chars
    e.g. 'Cisco Systems' -> 'cisco_systems'
         'IOS-XE'        -> 'ios_xe'
         'C9300-48P'     -> 'c9300_48p'
    """
    if not value:
        return "*"
    value = value.lower()
    value = re.sub(r'[\s\-/]+', '_', value)
    value = re.sub(r'[^a-z0-9_.]+', '', value)
    return value or "*"


def _build_device_cpes(device):
    """
    Build a list of CPE 2.3 strings to query NVD for a given device.
    Uses:
      - Manufacturer from device.device_type.manufacturer.name
      - Product from device.platform.name (preferred) or device_type.model
      - Version from the software_version custom field (set by netbox_software_tracker)

    Returns a list of (cpe_string, label) tuples covering both
    'o' (OS/firmware) and 'a' (application) part types.
    """
    cpes = []

    # Get version from custom field
    version = device.custom_field_data.get(SW_TRACKER_CF) or "*"
    version = _normalize_cpe_component(str(version)) if version != "*" else "*"

    # Get vendor
    try:
        vendor = _normalize_cpe_component(device.device_type.manufacturer.name)
    except AttributeError:
        vendor = "*"

    # Build product candidates — platform name is most accurate for software CVEs
    products = []
    if device.platform:
        products.append((
            _normalize_cpe_component(device.platform.name),
            f"Platform: {device.platform.name}"
        ))
    # Always include device type model as a fallback
    products.append((
        _normalize_cpe_component(device.device_type.model),
        f"Device Type: {device.device_type.model}"
    ))

    # Generate CPEs for OS ('o') and application ('a') part types
    # Hardware ('h') is intentionally excluded — most CVEs are software
    for product, label in products:
        for part in ('o', 'a'):
            part_label = 'OS/Firmware' if part == 'o' else 'Application'
            cpe = f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
            cpes.append((cpe, f"{label} [{part_label}]"))

    return cpes


def get_device_cves(device, return_url=""):
    """
    Query NVD for CVEs affecting the given device based on its
    software version (from the netbox_software_tracker custom field),
    manufacturer, and platform/device type.

    Returns a list of parsed CVE dicts ready for CveTable.
    """
    cpes = _build_device_cpes(device)
    if not cpes:
        return [], []

    proxies = _get_proxies()
    headers = _get_nvd_headers()
    results = []
    cpes_used = []

    for cpe_string, label in cpes:
        try:
            r = requests.get(
                NVD_CVE_URI,
                params={"cpeName": cpe_string},
                headers=headers,
                proxies=proxies,
                timeout=15,
            )
            r.raise_for_status()
            entries = r.json().get("vulnerabilities", [])
            if entries:
                cpes_used.append((cpe_string, label, len(entries)))
                results.extend(_parse_cve_entries(entries, return_url))
        except Exception as e:
            logger.warning("NVD CVE lookup failed for CPE %s: %s", cpe_string, e)

    # Deduplicate by CVE ID, preserving order
    seen = set()
    deduped = []
    for r in results:
        if r["id"] not in seen:
            seen.add(r["id"])
            deduped.append(r)

    return deduped, cpes_used


class DeviceCVEView(ObjectPermissionRequiredMixin, View):
    """
    A tab on the Device detail page that queries NVD for CVEs
    matching the device's software version, manufacturer, and platform.
    Requires netbox_software_tracker to populate the software_version
    custom field on devices.
    """
    queryset = Device.objects.all()
    template_name = "nb_risk/device_cve_tab.html"

    def get_required_permission(self):
        return get_permission_for_model(Device, "view")

    def get(self, request, pk):
        device = get_object_or_404(Device, pk=pk)
        return_url = request.build_absolute_uri()
        sw_version = device.custom_field_data.get(SW_TRACKER_CF)

        cves, cpes_used = [], []
        if sw_version:
            cves, cpes_used = get_device_cves(device, return_url)

        table = tables.CveTable(cves)

        return render(
            request,
            self.template_name,
            {
                "object": device,
                "table": table,
                "cves": cves,
                "cpes_used": cpes_used,
                "sw_version": sw_version,
                "sw_tracker_cf": SW_TRACKER_CF,
                "active_tab": "cve",
            },
        )
