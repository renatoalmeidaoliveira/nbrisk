from netbox.plugins.utils import get_plugin_config
from dcim.models import Device, Site, DeviceType
from tenancy.models import Tenant
from virtualization.models import VirtualMachine

from utilities.views import ViewTab, register_model_view
from django.contrib.contenttypes.models import ContentType
from django.shortcuts import get_object_or_404
from django.conf import settings
from django.urls import reverse

from django.views.generic import View
from django.shortcuts import redirect, render

from utilities.views import ObjectPermissionRequiredMixin
from utilities.permissions import get_permission_for_model
from netbox.views import generic
from utilities.views import ViewTab, register_model_view

import hashlib
import logging
import re
import requests
from concurrent.futures import ThreadPoolExecutor, as_completed
from django.core.cache import cache

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
    Normalize a vendor/product string to a CPE 2.3 component.
    - Lowercase
    - Replace spaces with underscores (spaces are never valid in CPE)
    - Preserve hyphens — NVD uses them in many product names (e.g. 'nx-os', 'ios-xe')
    - Strip any remaining non-alphanumeric/hyphen/underscore/dot chars
    e.g. 'Cisco Systems' -> 'cisco_systems'
         'NX-OS'         -> 'nx-os'   (matches NVD exactly)
         'IOS-XE'        -> 'ios-xe'  (matches NVD exactly)
         'C9300-48P'     -> 'c9300-48p'
    NOTE: use _normalize_cpe_version() for version strings.
    """
    if not value:
        return "*"
    value = value.lower()
    value = re.sub(r'\s+', '_', value)          # spaces only -> underscores
    value = re.sub(r'/+', '-', value)            # slashes -> hyphens
    value = re.sub(r'[^a-z0-9_.\-]+', '', value) # strip everything else
    return value or "*"


def _normalize_cpe_version(value):
    """
    Normalize a software version string for use in CPE 2.3 queries.
    Preserves Cisco-style parenthetical patch suffixes by percent-encoding
    them, e.g. '16.1(4h)' -> '16.1\\(4h\\)' which NVD understands.
    Also returns a stripped major.minor fallback for broader matching.
    Returns (full_version, fallback_version) tuple.
    """
    if not value:
        return "*", "*"
    # Escape parentheses for CPE 2.3 WFN format
    full = value.strip().lower()
    full = full.replace('(', '\\(').replace(')', '\\)')
    # Fallback: strip everything after first non-numeric/dot char
    fallback = re.split(r'[^0-9.]', value.strip())[0].rstrip('.')
    if fallback == full.replace('\\(', '(').replace('\\)', ')'):
        fallback = None  # no point querying the same value twice
    return full, fallback or None


def _get_cpes_from_mapping(device, full_version, fallback_version):
    """
    Look up CPEMapping records for this device's platform or device_type.
    Returns a list of (cpe_string, label) tuples ready for NVD queries.
    Device type mappings take precedence over platform mappings.
    """
    # Import here to avoid circular import at module load
    from .models import CPEMapping

    cpes = []
    mappings = []

    # Device type is most specific — check first
    if device.device_type:
        mappings = list(CPEMapping.objects.filter(device_type=device.device_type))

    # Fall back to platform
    if not mappings and device.platform:
        mappings = list(CPEMapping.objects.filter(platform=device.platform))

    if not mappings:
        return []

    versions_to_try = [(full_version, "")]
    if fallback_version:
        versions_to_try.append((fallback_version, " [major.minor fallback]"))

    for mapping in mappings:
        scope = str(mapping.platform or mapping.device_type)
        verified_tag = " [verified]" if mapping.verified else ""
        for version, ver_suffix in versions_to_try:
            cpe = mapping.build_cpe(version)
            cpes.append((cpe, f"{scope}{verified_tag}{ver_suffix}"))

    return cpes


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

    # Get version from custom field — use dedicated version normalizer
    raw_version = device.custom_field_data.get(SW_TRACKER_CF)
    if raw_version:
        full_version, fallback_version = _normalize_cpe_version(str(raw_version))
    else:
        full_version, fallback_version = "*", None

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

    # Determine if this is a Nexus device and which series
    # so we can use the target_sw component in CPE (8th field)
    nexus_target_sw = None
    for product, _ in products:
        family = _extract_product_family(device.device_type.model)
        if family and 'nexus' in family.lower():
            series = re.search(r'(\d+)', family)
            if series:
                nexus_target_sw = f"nexus_{series.group(1)}_series"
            break

    # Generate CPEs. For Nexus devices include the target_sw field
    # (8th component) which NVD uses to scope Nexus-specific entries:
    #   cpe:2.3:a:cisco:nx-os:{ver}:*:*:*:*:nexus_9000_series:*:*
    # Also generate generic CPEs as fallback.
    # Hardware ('h') is intentionally excluded.
    versions_to_try = [(full_version, "")]
    if fallback_version and fallback_version != full_version:
        versions_to_try.append((fallback_version, " [major.minor fallback]"))

    for product, prod_label in products:
        for version, ver_suffix in versions_to_try:
            for part in ('o', 'a'):
                part_label = 'OS/Firmware' if part == 'o' else 'Application'
                # Nexus-targeted CPE (most specific)
                if nexus_target_sw:
                    cpe = f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:{nexus_target_sw}:*:*"
                    cpes.append((cpe, f"{prod_label} [{part_label}] Nexus-targeted{ver_suffix}"))
                # Generic CPE
                cpe = f"cpe:2.3:{part}:{vendor}:{product}:{version}:*:*:*:*:*:*:*"
                cpes.append((cpe, f"{prod_label} [{part_label}]{ver_suffix}"))

    return cpes


# Cache timeout for NVD results — 6 hours
NVD_CACHE_TIMEOUT = 6 * 60 * 60


def _extract_product_family(model):
    """
    Extract a product family string from a device model name for use
    in NVD keyword searches. Strips specific suffixes to get the series.

    e.g. 'Nexus 9396PX'     -> 'Nexus 9000'
         'Nexus 5672UP'     -> 'Nexus 5000'
         'ASR 1001-X'       -> 'ASR 1001'
         'Catalyst 9300-48P'-> 'Catalyst 9300'
         'C9300-48P'        -> 'Catalyst 9300'
    """
    if not model:
        return None

    # Nexus series: extract series number and round to nearest thousand
    # e.g. 'Nexus 9396PX' -> series 9000, 'Nexus 5672UP' -> 5000
    nexus_match = re.search(r'[Nn]exus\s*(\d)(\d{3})', model)
    if nexus_match:
        series = nexus_match.group(1) + '000'
        return f"Nexus {series}"

    # Bare Nexus model numbers like 'N9K-C9396PX'
    n_series_match = re.search(r'[Nn](\d)K', model)
    if n_series_match:
        series = n_series_match.group(1) + '000'
        return f"Nexus {series}"

    # Catalyst: 'Catalyst 9300-48P' or 'C9300-48P' -> 'Catalyst 9300'
    catalyst_match = re.search(r'(?:[Cc]atalyst\s*|[Cc])(\d{4})', model)
    if catalyst_match:
        return f"Catalyst {catalyst_match.group(1)}"

    # ASR: 'ASR 1001-X' -> 'ASR 1001'
    asr_match = re.search(r'ASR\s*(\d+)', model, re.IGNORECASE)
    if asr_match:
        return f"ASR {asr_match.group(1)}"

    # ISR: 'ISR 4321' -> 'ISR 4000'
    isr_match = re.search(r'ISR\s*(\d)(\d{3})', model, re.IGNORECASE)
    if isr_match:
        series = isr_match.group(1) + '000'
        return f"ISR {series}"

    # Firepower: 'FPR-2140' -> 'Firepower 2100'
    fpr_match = re.search(r'(?:FPR|Firepower)[\s-]*(\d)(\d{2})', model, re.IGNORECASE)
    if fpr_match:
        series = fpr_match.group(1) + '00'
        return f"Firepower {series}"

    return None


def _fetch_cve_by_cpe(cpe_string, label, headers, proxies, return_url):
    """Fetch CVEs for a single CPE string. Designed for parallel execution."""
    try:
        r = requests.get(
            NVD_CVE_URI,
            params={"cpeName": cpe_string},
            headers=headers,
            proxies=proxies,
            timeout=8,
        )
        r.raise_for_status()
        entries = r.json().get("vulnerabilities", [])
        if entries:
            return (cpe_string, label, _parse_cve_entries(entries, return_url))
    except Exception as e:
        logger.warning("NVD CVE lookup failed for CPE %s: %s", cpe_string, e)
    return None


def get_device_cves(device, return_url=""):
    """
    Query NVD for CVEs affecting the given device based on its
    software version (from the netbox_software_tracker custom field),
    manufacturer, and platform/device type.

    Results are cached in Redis for NVD_CACHE_TIMEOUT seconds to avoid
    repeated API calls on page reload. CPE queries run in parallel.

    Returns (cve_list, cpes_used) tuple.
    """
    # Get version components first
    raw_version = device.custom_field_data.get(SW_TRACKER_CF)
    if raw_version:
        full_version, fallback_version = _normalize_cpe_version(str(raw_version))
    else:
        full_version, fallback_version = "*", None

    # Try CPEMapping records first (user-verified, precise)
    cpes = _get_cpes_from_mapping(device, full_version, fallback_version)
    using_mapping = bool(cpes)

    # Fall back to heuristic CPE generation if no mappings configured
    if not cpes:
        cpes = _build_device_cpes(device)

    if not cpes:
        return [], []

    # Build a stable cache key from the device's CPE strings
    cache_key = "nb_risk:device_cves:" + hashlib.md5(
        "|".join(cpe for cpe, _ in cpes).encode()
    ).hexdigest()

    cached = cache.get(cache_key)
    if cached is not None:
        logger.debug("nb_risk: cache hit for device %s CVEs", device.pk)
        return cached

    proxies = _get_proxies()
    headers = _get_nvd_headers()
    results = []
    cpes_used = []

    # Run all CPE queries in parallel
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {
            executor.submit(_fetch_cve_by_cpe, cpe, label, headers, proxies, return_url): (cpe, label)
            for cpe, label in cpes
        }
        for future in as_completed(futures):
            result = future.result()
            if result:
                cpe_string, label, entries = result
                cpes_used.append((cpe_string, label, len(entries)))
                results.extend(entries)

    # Deduplicate by CVE ID, preserving order
    seen = set()
    deduped = []
    for r in results:
        if r["id"] not in seen:
            seen.add(r["id"])
            deduped.append(r)

    result_tuple = (deduped, cpes_used)
    cache.set(cache_key, result_tuple, NVD_CACHE_TIMEOUT)
    return result_tuple


@register_model_view(Device, name='device_cve')
class DeviceCVEView(generic.ObjectView):
    """
    A tab on the Device detail page that queries NVD for CVEs
    matching the device's software version, manufacturer, and platform.
    Requires the software_version custom field to be populated
    (e.g. by netbox_software_tracker).
    """
    queryset = Device.objects.all()
    template_name = "nb_risk/device_cve_tab.html"

    tab = ViewTab(
        label="CVEs",
        permission="dcim.view_device",
        weight=10000,
    )

    def get_extra_context(self, request, instance):
        from .models import CPEMapping
        sw_version = instance.custom_field_data.get(SW_TRACKER_CF)
        return_url = request.build_absolute_uri()

        cves, cpes_used = [], []
        if sw_version:
            cves, cpes_used = get_device_cves(instance, return_url)

        # Check if a CPE mapping exists for this device
        has_mapping = CPEMapping.objects.filter(
            device_type=instance.device_type
        ).exists() or (
            instance.platform and
            CPEMapping.objects.filter(platform=instance.platform).exists()
        )

        table = tables.CveTable(cves)

        return {
            "table": table,
            "cves": cves,
            "cpes_used": cpes_used,
            "sw_version": sw_version,
            "sw_tracker_cf": SW_TRACKER_CF,
            "has_mapping": has_mapping,
            "cpe_lookup_url": reverse('plugins:nb_risk:cpe_lookup'),
            "cpemapping_add_url": reverse('plugins:nb_risk:cpemapping_add'),
        }
