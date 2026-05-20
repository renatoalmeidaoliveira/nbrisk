"""
FIRST.org Exploit Prediction Scoring System (EPSS) integration.

API: https://api.first.org/data/v1/epss
- No authentication required
- Bulk queries: comma-separated CVE IDs (up to 100 per request)
- Updated daily

Provides:
  fetch_epss_scores(cve_ids)   Fetch EPSS scores for a list of CVE IDs
  sync_epss_to_db()            Update all Vulnerability records with EPSS data
  enrich_cve_results(cve_list) Tag CVE dicts with EPSS scores in-place
"""

import logging
import requests
from datetime import date
from django.core.cache import cache

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"
EPSS_CACHE_PREFIX = "nb_risk:epss:"
EPSS_CACHE_TIMEOUT = 24 * 60 * 60  # 24 hours — EPSS updates daily
EPSS_CHUNK_SIZE = 100  # max CVEs per API request


def fetch_epss_scores(cve_ids, timeout=15):
    """
    Fetch EPSS scores for a list of CVE IDs from the FIRST.org API.
    Automatically chunks requests into groups of EPSS_CHUNK_SIZE.

    Returns a dict: {cve_id: {'epss': float, 'percentile': float, 'date': str}}
    """
    if not cve_ids:
        return {}

    results = {}

    # Deduplicate and uppercase
    cve_ids = list({c.upper() for c in cve_ids if c})

    # Process in chunks of 100
    for i in range(0, len(cve_ids), EPSS_CHUNK_SIZE):
        chunk = cve_ids[i:i + EPSS_CHUNK_SIZE]
        try:
            r = requests.get(
                EPSS_API_URL,
                params={"cve": ",".join(chunk)},
                timeout=timeout,
            )
            r.raise_for_status()
            data = r.json()
            for entry in data.get("data", []):
                cve = entry.get("cve", "").upper()
                if cve:
                    results[cve] = {
                        "epss": float(entry.get("epss", 0)),
                        "percentile": float(entry.get("percentile", 0)),
                        "date": entry.get("date", ""),
                    }
        except Exception as e:
            logger.warning("nb_risk: EPSS fetch failed for chunk starting at %d: %s", i, e)

    return results


def sync_epss_to_db(stdout=None):
    """
    Fetch EPSS scores for all Vulnerability records that have a CVE ID
    and update them in the database.

    Returns (updated_count, total_count) tuple.
    """
    from .models import Vulnerability

    def log(msg):
        logger.info(msg)
        if stdout:
            stdout.write(msg + "\n")

    vulns = list(Vulnerability.objects.exclude(cve="").values_list('pk', 'cve'))
    if not vulns:
        log("No vulnerabilities with CVE IDs found.")
        return 0, 0

    log(f"Fetching EPSS scores for {len(vulns)} vulnerabilities...")
    cve_ids = [cve for _, cve in vulns]
    scores = fetch_epss_scores(cve_ids)
    log(f"Received EPSS scores for {len(scores)} CVEs.")

    updated = 0
    for pk, cve in vulns:
        score_data = scores.get(cve.upper())
        if not score_data:
            continue

        epss_date = None
        try:
            epss_date = date.fromisoformat(score_data["date"])
        except (ValueError, TypeError):
            pass

        Vulnerability.objects.filter(pk=pk).update(
            epss_score=score_data["epss"],
            epss_percentile=score_data["percentile"],
            epss_date=epss_date,
        )
        updated += 1

    # Invalidate any cached EPSS data
    cache.delete_pattern(f"{EPSS_CACHE_PREFIX}*") if hasattr(cache, 'delete_pattern') else None

    log(f"EPSS sync complete: {updated}/{len(vulns)} vulnerabilities updated.")
    return updated, len(vulns)


def fetch_epss_for_cves(cve_ids):
    """
    Fetch EPSS scores with per-CVE caching. Used for real-time enrichment
    of NVD search results and Device CVE tab results.

    Returns a dict: {cve_id: {'epss': float, 'percentile': float}}
    """
    if not cve_ids:
        return {}

    results = {}
    uncached = []

    for cve_id in cve_ids:
        cve_upper = cve_id.upper()
        cached = cache.get(f"{EPSS_CACHE_PREFIX}{cve_upper}")
        if cached is not None:
            results[cve_upper] = cached
        else:
            uncached.append(cve_upper)

    if uncached:
        fresh = fetch_epss_scores(uncached)
        for cve, data in fresh.items():
            cache.set(f"{EPSS_CACHE_PREFIX}{cve}", data, EPSS_CACHE_TIMEOUT)
            results[cve] = data

    return results


def enrich_cve_results(cve_list):
    """
    Add EPSS score and percentile to a list of CVE dicts in-place.
    Uses per-CVE caching so repeat lookups are instant.
    """
    if not cve_list:
        return cve_list

    cve_ids = [c.get("id", "") for c in cve_list if c.get("id")]
    scores = fetch_epss_for_cves(cve_ids)

    for cve in cve_list:
        cve_id = cve.get("id", "").upper()
        score_data = scores.get(cve_id, {})
        cve["epss_score"] = score_data.get("epss")
        cve["epss_percentile"] = score_data.get("percentile")

    return cve_list
