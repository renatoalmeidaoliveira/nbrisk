"""
CPE Lookup Assistant — searches the NVD CPE dictionary and lets users
create CPEMapping records directly from results.
"""
import requests
import logging

from django.shortcuts import render, redirect
from django.views.generic import View

from utilities.views import ObjectPermissionRequiredMixin
from utilities.permissions import get_permission_for_model

from . import models
from .cve import _get_nvd_headers, _get_proxies

logger = logging.getLogger(__name__)

NVD_CPE_URI = "https://services.nvd.nist.gov/rest/json/cpes/2.0"


class CPELookupView(ObjectPermissionRequiredMixin, View):
    """
    Search the NVD CPE dictionary by keyword and display matching CPE strings.
    Each result has a 'Create Mapping' button that pre-populates the
    CPEMapping add form with the vendor, product, part, and target_sw fields.
    """
    queryset = models.CPEMapping.objects.all()
    template_name = "nb_risk/cpe_lookup.html"

    def get_required_permission(self):
        return get_permission_for_model(models.CPEMapping, "add")

    def get(self, request):
        keyword = request.GET.get("keyword", "").strip()
        results = []
        total = 0
        error = None

        if keyword:
            try:
                r = requests.get(
                    NVD_CPE_URI,
                    params={"keywordSearch": keyword, "resultsPerPage": 20},
                    headers=_get_nvd_headers(),
                    proxies=_get_proxies(),
                    timeout=10,
                )
                r.raise_for_status()
                data = r.json()
                total = data.get("totalResults", 0)

                for product in data.get("products", []):
                    cpe = product.get("cpe", {})
                    cpe_name = cpe.get("cpeName", "")
                    title = cpe.get("titles", [{}])[0].get("title", "")
                    deprecated = cpe.get("deprecated", False)

                    # Parse components from CPE 2.3 string
                    parts = cpe_name.split(":")
                    if len(parts) >= 6:
                        part = parts[2]
                        vendor = parts[3]
                        product_name = parts[4]
                        # 8th component (index 7) is target_sw
                        target_sw = parts[7] if len(parts) > 7 and parts[7] not in ('*', '-') else ''

                        results.append({
                            "cpe_name": cpe_name,
                            "title": title,
                            "deprecated": deprecated,
                            "part": part,
                            "vendor": vendor,
                            "product": product_name,
                            "target_sw": target_sw,
                        })

            except Exception as e:
                logger.error("CPE lookup failed: %s", e)
                error = str(e)

        return render(request, self.template_name, {
            "keyword": keyword,
            "results": results,
            "total": total,
            "error": error,
        })
