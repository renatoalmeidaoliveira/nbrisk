import django_tables2 as tables
from django.urls import reverse
from django.utils.safestring import mark_safe
from django.utils.http import urlencode


class CreateColumn(tables.Column):
    attrs = {"td": {"class": "text-end text-nowrap"}}

    def render(self, record):
        cve = record.get("id", "")
        description = record.get("description", "")
        cvss_version = record.get("cvssVersion", "")

        # Build notes to include CVSS version information
        notes = description
        if cvss_version:
            notes = f"[CVSSv{cvss_version}] {description}"

        url = reverse("plugins:nb_risk:vulnerability_add")
        query = {
            "cve": cve,
            "notes": notes,
            "name": cve,
            "cvssaccessVector": record.get("accessVector", ""),
            "cvssaccessComplexity": record.get("accessComplexity", ""),
            "cvssauthentication": record.get("authentication", ""),
            "cvssconfidentialityImpact": record.get("confidentialityImpact", ""),
            "cvssintegrityImpact": record.get("integrityImpact", ""),
            "cvssavailabilityImpact": record.get("availabilityImpact", ""),
            "cvssbaseScore": record.get("baseScore", ""),
        }
        if record.get("return_url"):
            query["return_url"] = record["return_url"]

        encoded_query = urlencode(query)
        url = f"{url}?{encoded_query}"

        html = f'<a href="{url}" class="btn btn-sm btn-primary" title="Import as Vulnerability"><i class="mdi mdi-plus-thick" aria-hidden="true"></i> Import</a>'
        return mark_safe(html)
