"""
CISA Known Exploited Vulnerabilities (KEV) catalog integration.

Feed URL: https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json
Updated:  Daily by CISA

Provides:
  - fetch_kev_catalog()       Download and parse the KEV feed
  - sync_kev_to_db()          Update Vulnerability records with KEV data
  - get_kev_set()             Return a set of CVE IDs in the catalog (cached)
  - enrich_cve_results()      Tag CVE dicts from NVD with KEV status
"""

import logging
import requests
from datetime import date
from django.core.cache import cache

logger = logging.getLogger(__name__)

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
KEV_CACHE_KEY = "nb_risk:kev_set"
KEV_CACHE_TIMEOUT = 6 * 60 * 60  # 6 hours


def fetch_kev_catalog(timeout=30):
    """
    Download and return the full CISA KEV catalog as a dict keyed by CVE ID.
    Returns {} on failure.
    """
    try:
        r = requests.get(KEV_FEED_URL, timeout=timeout)
        r.raise_for_status()
        data = r.json()
        catalog = {}
        for entry in data.get("vulnerabilities", []):
            cve_id = entry.get("cveID", "").upper()
            if cve_id:
                catalog[cve_id] = entry
        logger.info("nb_risk: fetched KEV catalog — %d entries", len(catalog))
        return catalog
    except Exception as e:
        logger.error("nb_risk: failed to fetch KEV catalog: %s", e)
        return {}


def get_kev_set():
    """
    Return a set of CVE IDs currently in the CISA KEV catalog.
    Result is cached for 6 hours. Falls back to DB query if cache miss.
    """
    cached = cache.get(KEV_CACHE_KEY)
    if cached is not None:
        return cached

    # Try to build from DB first (fast, no network)
    try:
        from .models import Vulnerability
        db_set = set(
            Vulnerability.objects.filter(in_kev=True)
            .values_list('cve', flat=True)
        )
        if db_set:
            cache.set(KEV_CACHE_KEY, db_set, KEV_CACHE_TIMEOUT)
            return db_set
    except Exception:
        pass

    # Fall back to fetching the feed
    catalog = fetch_kev_catalog()
    kev_set = set(catalog.keys())
    cache.set(KEV_CACHE_KEY, kev_set, KEV_CACHE_TIMEOUT)
    return kev_set


def sync_kev_to_db(stdout=None):
    """
    Download the CISA KEV catalog and update all Vulnerability records
    whose CVE ID appears in the catalog.

    Returns (updated_count, cleared_count, total_kev) tuple.
    """
    from .models import Vulnerability

    def log(msg):
        logger.info(msg)
        if stdout:
            stdout.write(msg + "\n")

    log("Fetching CISA KEV catalog...")
    catalog = fetch_kev_catalog()
    if not catalog:
        log("ERROR: Could not fetch KEV catalog.")
        return 0, 0, 0

    log(f"Catalog contains {len(catalog)} entries.")

    # Mark vulnerabilities that ARE in KEV
    updated = 0
    for cve_id, entry in catalog.items():
        qs = Vulnerability.objects.filter(cve__iexact=cve_id)
        if not qs.exists():
            continue

        date_added = None
        try:
            date_added = date.fromisoformat(entry.get("dateAdded", ""))
        except (ValueError, TypeError):
            pass

        due_date = None
        try:
            due_date = date.fromisoformat(entry.get("dueDate", ""))
        except (ValueError, TypeError):
            pass

        rows = qs.update(
            in_kev=True,
            kev_date_added=date_added,
            kev_ransomware_use=entry.get("knownRansomwareCampaignUse", ""),
            kev_required_action=entry.get("requiredAction", ""),
            kev_due_date=due_date,
            kev_vendor_project=entry.get("vendorProject", ""),
            kev_product=entry.get("product", ""),
        )
        updated += rows

    # Clear KEV flags for vulnerabilities no longer in the catalog
    cleared = Vulnerability.objects.filter(in_kev=True).exclude(
        cve__in=list(catalog.keys())
    ).update(
        in_kev=False,
        kev_date_added=None,
        kev_ransomware_use="",
        kev_required_action="",
        kev_due_date=None,
        kev_vendor_project="",
        kev_product="",
    )

    # Invalidate cache so get_kev_set() picks up fresh data
    cache.delete(KEV_CACHE_KEY)

    log(f"Sync complete: {updated} vulnerabilities updated, {cleared} flags cleared.")
    return updated, cleared, len(catalog)


def enrich_cve_results(cve_list):
    """
    Tag a list of CVE dicts (from NVD parsing) with KEV status.
    Adds 'in_kev': True/False to each dict in-place.
    Uses the cached KEV set for performance.
    """
    try:
        kev_set = get_kev_set()
        for cve in cve_list:
            cve['in_kev'] = cve.get('id', '').upper() in kev_set
    except Exception as e:
        logger.warning("nb_risk: KEV enrichment failed: %s", e)
        for cve in cve_list:
            cve.setdefault('in_kev', False)
    return cve_list
